#!/usr/bin/env python3

import argparse 
from pathlib import Path 
from collections import Counter, defaultdict, deque
import re 
import json
from datetime import datetime 
import ipaddress

# ========================================

class IpStats:
    """
    Статистика и агрегация данных по одному IP-адресу.

    Хранит три независимых среза: категориальные счётчики (коды, URL, методы,
    даты), числовые ряды (время ответа, длительность), и ошибки парсинга,
    привязанные к этому IP. `total_requests` — знаменатель для процентов
    в отчёте.

    Attributes:
        categorical (defaultdict[Counter]): Счётчики категориальных значений
            по полям (например, `categorical["method"]["GET"] == 42`).
        numeric (defaultdict[list]): Списки чисел по полям для расчёта
            среднего/мин/макс (например, `numeric["duration_ms"]`).
        errors (defaultdict[list]): Ошибки парсинга, сгруппированные по типу
            (например, `errors["date_parse_failed"]`).
        total_requests (int): Общее количество успешно учтённых записей для IP.
            Используется как база для процентных долей.
    """
    
    def __init__(self) -> None:
        self.categorical = defaultdict(Counter)
        self.numeric = defaultdict(list)
        self.errors = defaultdict(list)
        self.total_requests = 0

class GlobalError:
    """
    Счётчик глобальных ошибок парсинга с ограниченной выборкой примеров.

    Считает все ошибки, но хранит только первые `len_deque` уникальных
    примеров, обрезанных до `len_data` символов. Нужен для диагностики:
    «сколько всего» + «на что похоже», без раздувания памяти на больших логах.

    Attributes:
        count (int): Общее количество ошибочных событий.
        samples (deque): Первые уникальные примеры (не более `len_deque`).
        len_data (int): Максимальная длина одного примера в символах.
    """

    def __init__(self, len_deque: int = 5, len_data: int = 200) -> None:
        self.count = 0
        self.samples = deque(maxlen=len_deque)
        self.len_data = len_data

    def add(self, raw) -> None:
        self.count += 1
        if len(self.samples) < self.samples.maxlen:
            text = str(raw).rstrip()[:self.len_data]
            if text not in self.samples:
                self.samples.append(text)


class NginxParser:
    """
    Парсер access-логов Nginx (combined-подобный формат).

    Извлекает IP, дату, метод, URL и код ответа. Статистика агрегируется
    по IP-адресу: категориальные поля (метод, URL, код, дата) и ошибки
    парсинга. Строки, не соответствующие шаблону, попадают в
    `global_errors["parsing"]["not_match"]`.

    Attributes:
        log_pattern (re.Pattern): Регулярное выражение для строки лога.
        ip_analytics (defaultdict): Статистика по каждому IP (IpStats).
        time (str): Гранулярность агрегации даты (Y/m/d/H/M/S).
        global_errors (defaultdict): Ошибки, не привязанные к конкретному IP.
        values_info (dict): Человекочитаемые названия категорий для вывода.
    """

    def __init__(self, time: str) -> None:
        self.log_pattern = re.compile(r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>[^\]]+)\]\s\"(?P<method>[A-Z]+)\s(?P<url>\S*)(?:\sHTTP\S*)?\"\s(?P<code>\d{3})")
        self.ip_analytics = defaultdict(IpStats)
        self.time = time
        self.global_errors = defaultdict(lambda: defaultdict(GlobalError))
        self.values_info = {
            "code": "Коды ответов",            
            "url": "Самые запрашиваемые URL",
            "method": "Методы",
            "date": "Даты",
        }

    def parser_log(self, line: str) -> None:
        match = self.log_pattern.match(line)

        if not is_match(match, self, line):
            return
        
        dataset = match.groupdict()

        if not is_ip(dataset, self):
            return
        ip = dataset.pop("ip")
        is_date(dataset, self, "%d/%b/%Y:%H:%M:%S %z", self.time, ip, "date")

        for index, value in dataset.items():
            if value is None or value == '':
                self.ip_analytics[ip].errors[f"{index}_parse_failed"].append(f"Отсутствует {index}")
                continue
            self.ip_analytics[ip].categorical[index].update([value])
                
        self.ip_analytics[ip].total_requests += 1
        
class SyslogParser():
    """
    Парсер SSH-событий из syslog/auth.log.

    Распознаёт четыре типа сообщений sshd: Failed password, Invalid user,
    Connection closed by, authentication failure. Остальные строки
    считаются в `global_errors["syslog"]["unrecognized"]` и в статистику
    по IP не попадают.

    Attributes:
        fail_passwd (re.Pattern): Шаблон для «Failed password …».
        con_clos (re.Pattern): Шаблон для «Connection closed by …».
        inv_usr (re.Pattern): Шаблон для «Invalid user …».
        authen_fail (re.Pattern): Шаблон для PAM «authentication failure».
        ip_analytics (defaultdict): Статистика по каждому IP (IpStats).
        time (str): Гранулярность агрегации даты (Y/m/d/H/M/S).
        global_errors (defaultdict): Нераспознанные строки и общие ошибки.
        values_info (dict): Человекочитаемые названия полей для вывода.
    """

    def __init__(self, time: str) -> None:

        self.fail_passwd = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Failed)\spassword\sfor\s(?:invalid user\s)?(?P<name>\S+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.con_clos = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Connection)\sclosed\sby\s(?:authenticating\suser\s|invalid\suser\s)?(?P<name>\S+)\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.inv_usr = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s(?P<error>Invalid)\suser\s(?P<name>\S+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\sport\s(?P<port>\d+)")
        self.authen_fail = re.compile(r"^(?P<date>\w+\s+\d{1,2}\s\S+|\S+)\s\S+\ssshd\[(?P<pid>\d+)\]:\s\S+\s(?P<error>authentication)\sfailure;.*?logname=(?P<logname>\S*).*?uid=(?P<uid>\d*).*?euid=(?P<euid>\d*).*?tty=(?P<tty>\S*).*?ruser=(?P<ruser>\S*).*?rhost=(?P<ip>\d+(?:\.\d{1,3}){3}).*?user=(?P<name>\S*)")
        self.global_errors = defaultdict(lambda: defaultdict(GlobalError))
        self.ip_analytics = defaultdict(IpStats)
        self.time = time

        self.values_info = {
            "error": "Ошибка",            
            "date": "Дата и время события",
            "pid": "Идентификаторы процесса (PID)",
            "name": "Имя пользователя (или процесса)",
            "port": "Сетевые или терминальные порты",
            "logname": "Исходные логины пользователей (logname)",
            "uid": "Реальные идентификаторы пользователей (UID)",
            "euid": "Эффективные идентификаторы пользователей (EUID)",
            "tty": "Имена терминалов (TTY)",
            "ruser": "Имена удалённых пользователей (ruser)"
        }

    def parser_log(self, line: str) -> None:
        if "Invalid user" in line:
            match = self.inv_usr.match(line)
        elif "authentication failure" in line:
            match = self.authen_fail.match(line)
        elif "Connection closed by" in line:
            match = self.con_clos.match(line)
        elif "Failed password" in line:
            match = self.fail_passwd.match(line)
        else:
            self.global_errors["syslog"]["unrecognized"].add(line.rstrip("\n"))
            return

        if not is_match(match, self, line):
            return
        dataset = match.groupdict()

        if not is_ip(dataset, self):
            return 
        ip = dataset.pop("ip")

        is_date(dataset, self, "%b %d %H:%M:%S", self.time, ip, "date", True)

        for index, value in dataset.items():
            if value is None or value == '':
                self.ip_analytics[ip].errors[f"{index}_parse_failed"].append(f"Отсутствует {index}")
                continue
            self.ip_analytics[ip].categorical[index].update([value])
                
        self.ip_analytics[ip].total_requests += 1
    
class JsonAppParser:
    """
    Парсер структурированных JSON-логов приложений (по одной записи на строку).

    Поля верхнего уровня и вложенные объекты разворачиваются в плоский
    словарь через `flatten_dict`. Поля `duration_ms` и `response_time`
    трактуются как числовые (среднее/мин/макс), остальные — как
    категориальные. Списки сохраняются как JSON-строки. Невалидный JSON
    считается в `global_errors["json"]["invalid"]`.

    Attributes:
        ip_analytics (defaultdict): Статистика по каждому IP (IpStats).
        time (str): Гранулярность агрегации даты (Y/m/d/H/M/S).
        global_errors (defaultdict): Ошибки, не привязанные к конкретному IP.
        values_info (dict): Человекочитаемые названия полей для вывода.
    """

    def __init__(self, time: str) -> None:
        self.ip_analytics = defaultdict(IpStats)
        self.time = time
        self.global_errors = defaultdict(lambda: defaultdict(GlobalError))
        self.values_info = {
            "level": "Уровень логирования (INFO, ERROR, DEBUG...)",
            "service": "Сервис или микросервис",
            "message": "Текст сообщения",
            "user_id": "Идентификатор пользователя",
            "status_code": "HTTP-код ответа",
            "component": "Компонент / модуль",
            "error_code": "Код ошибки (бизнес-логика)",
            "exception": "Тип исключения (класс ошибки)",
            "duration_ms": "Длительность обработки, мс",
            "response_time": "Время ответа, мс"
        }

    def flatten_dict(self, data: dict, old_key='', sep='_') -> dict:
        arr = []
        for index, value in data.items():
            new_key = f"{old_key}{sep}{index}" if old_key else index
            if isinstance(value, dict):
                arr.extend(self.flatten_dict(value, new_key).items())
            else:
                arr.append((new_key, value))
        return dict(arr)

    def parser_log(self, line: str) -> None:
        try:
            data = json.loads(line)
        except Exception:
            self.global_errors["json"]["invalid"].add(line)
            return

        if not is_ip(data, self):
            return
        ip = data.pop("ip")

        is_date(data, self, "%Y-%m-%dT%H:%M:%SZ", self.time, ip, "timestamp")

        flat_dict = self.flatten_dict(data)
        
        for index, value in flat_dict.items():
            if value is None or value == '':
                self.ip_analytics[ip].errors[f"{index}_missing"].append(f"Отсутствует {index}")
                continue

            if index in ["duration_ms", "response_time"]:
                if type(value) in (int, float):
                    self.ip_analytics[ip].numeric[index].append(value)
                else:
                    try:
                        self.ip_analytics[ip].numeric[index].append(float(value))
                    except (ValueError, TypeError):
                        self.ip_analytics[ip].errors[f"{index}_not_number"].append(repr(value))
                continue
            elif isinstance(value, list):
                self.ip_analytics[ip].categorical[index].update([json.dumps(value, ensure_ascii=False)])
            else:
                self.ip_analytics[ip].categorical[index].update([value])
        self.ip_analytics[ip].total_requests += 1

class DatabaseSlowQueryParser:
    """
    Парсер slow query log MySQL/MariaDB.

    Запись состоит из набора строк-комментариев (`# Time:`, `# User@Host:`,
    `# Query_time:`) и следующего за ними SQL-запроса. Запись фиксируется
    в `finalize()` — либо при встрече следующего `# Time:`, либо в конце
    файла. Текст запроса нормализуется в «отпечаток»: числа заменяются
    на `?`, что позволяет группировать однотипные запросы.

    Attributes:
        re_time (re.Pattern): Шаблон строки `# Time:`.
        re_user (re.Pattern): Шаблон строки `# User@Host:`.
        re_metrics (re.Pattern): Шаблон строки `# Query_time:`.
        re_sql_operation (re.Pattern): Определение типа SQL-операции.
        re_sql_fingerprint (re.Pattern): Замена чисел в запросе на `?`.
        ip_analytics (defaultdict): Статистика по каждому IP (IpStats).
        sql_arr (list): Накопленные строки текущего SQL-запроса.
        dict_data (dict): Поля текущей записи (заполняются по мере чтения).
        time (str): Гранулярность агрегации даты (Y/m/d/H/M/S).
        global_errors (defaultdict): Ошибки, не привязанные к конкретному IP.
        values_info (dict): Человекочитаемые названия полей для вывода.
    """

    def __init__(self, time: str) -> None:

        self.re_time = re.compile(r"^#\sTime:\s(?P<time>\S+)$")
        self.re_user = re.compile(r"^#\sUser@Host:\s(?P<userhost>\S+)\s@.+\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]\s+Id:\s(?P<id>\d+)$")
        self.re_metrics = re.compile(r"^#\sQuery_time:\s(?P<query_time>\S+)\s+Lock_time:\s(?P<lock_time>\S+)\s+Rows_sent:\s(?P<rows_sent>\d+)\s+Rows_examined:\s(?P<rows_examined>\d+)$")
        self.re_sql_operation = re.compile(r"^\s*(?P<operation>\w+)")
        self.re_sql_fingerprint = re.compile(r"\b\d+(?:[\.\-]?\d*)*\b")
        self.global_errors = defaultdict(lambda: defaultdict(GlobalError))
        self.ip_analytics = defaultdict(IpStats)

        self.sql_arr = []
        self.dict_data = dict()
        self.time = time

        self.values_info = {
            "time": "Время выполнения или фиксации запроса",
            "userhost": "Пользователь и хост, выполнившие запрос (User[pass] @ Host)",
            "id": "Идентификатор потока / соединения (Connection ID)",
            "operation": "Тип операции или текст SQL-запроса",
            "fingerprint": "Абстрактный отпечаток (шаблон) запроса без конкретных значений",
            "query_time": "Общее время выполнения запроса (в секундах)",
            "lock_time": "Время, потраченное на ожидание блокировок таблиц",
            "rows_sent": "Количество строк, отправленных клиенту",
            "rows_examined": "Количество строк, проверенных сервером при выборке",
        }

    def parser_log(self, line: str) -> None:

        match = None

        if not line:
            return

        if line.startswith("# Time:"):
            self.finalize()
            match = self.re_time.search(line)
        elif line.startswith("# User@Host:"):
            match = self.re_user.search(line)
        elif line.startswith("# Query_time:"):
            match = self.re_metrics.search(line)
        else:
            self.sql_arr.append(line)
            return
        
        if not is_match(match, self, line):
            return

        self.dict_data.update(match.groupdict())

    def finalize(self):
        if self.dict_data and is_ip(self.dict_data, self):

            ip = self.dict_data.pop("ip")
            sql_txt = "\t\t".join(self.sql_arr)
            sql_match = self.re_sql_operation.search(sql_txt)
            sql_txt = self.re_sql_fingerprint.sub("?", sql_txt)

            is_date(self.dict_data, self, "%Y-%m-%dT%H:%M:%S.%f%z", self.time, ip, "time")

            sql_operation = sql_match.group("operation") if sql_match else "UNKNOWN"

            self.ip_analytics[ip].categorical["operation"].update([sql_operation])
            self.ip_analytics[ip].categorical["fingerprint"].update([sql_txt])

            for key, value in self.dict_data.items():
                if value is None or value == '':
                    self.ip_analytics[ip].errors[f"{key}_parse_failed"].append(f"Отсутствует {key}")
                    continue
                
                if key in ["time", "userhost","id"]:
                    self.ip_analytics[ip].categorical[key].update([value])
                elif key in ["query_time", "lock_time", "rows_sent", "rows_examined"]:
                    try:
                        self.ip_analytics[ip].numeric[key].append(float(value))
                    except (ValueError, TypeError):
                        self.ip_analytics[ip].errors["not_number"].append(f"{value}")
                    
            self.ip_analytics[ip].total_requests += 1

        self.dict_data.clear()
        self.sql_arr.clear()

        
        

# ========================================

def build_report(obj: object, top_n: int) -> dict:
    ips = []
    sorted_ips = sorted(obj.ip_analytics.items(), key=lambda item: item[1].total_requests, reverse=True)

    for ip, info in sorted_ips[:top_n]:
        total = info.total_requests or 1
        ips.append({
            "ip": ip,
            "total_requests": info.total_requests,
            "categorical": {
                field: [
                    {"value": v, "count": c, "pct": round(c / total * 100, 1)}
                    for v, c in counter.most_common(3)
                ]
                for field, counter in info.categorical.items()
            },
            "numeric": {
                field: {
                    "avg": round(sum(v) / len(v), 3), 
                    "min": round(min(v), 3),
                    "max": round(max(v), 3), 
                    "count": len(v),
                }
                for field, v in info.numeric.items() if v
            },
            "errors":{
                k: list(v)[:3] for k, v in info.errors.items() if v
            }
        })

    global_errors = {
        category: {
            typ: {"count":stat.count, "samples": list(stat.samples) }
            for typ, stat in typs.items()
        }
        for category, typs in obj.global_errors.items()
    }

    return {"top_ips": ips, "global_errors": global_errors} 


def display(report: dict, values_info: dict) -> None:
    print(f"\n{3 * '='} ДЕТАЛЬНЫЙ АНАЛИЗ ТОП-{len(report['top_ips'])} АКТИВНЫХ IP {3 * '='}")
    for info in report["top_ips"]:
        print(f"\n[+] IP-адрес: {info['ip']} (Всего запросов: {info['total_requests']})")
        for categoria, values in info['categorical'].items():
            if values:
                if values_info.get(categoria):
                    print(f"\t{values_info[categoria]}:")
                else:
                    print(f"\t{categoria}:")
                for it in values:
                    print(f"\t\t\t- {it['value']}: {it['count']} раз ({it['pct']}%)")  
        for index, values in info["numeric"].items():
            if values:
                if values_info.get(index):
                    print(f"\t{values_info[index]}:")
                else:
                    print(f"\t{index}:")
                print(f"\t\t- Среднее: {values['avg']}")
                print(f"\t\t- Максимум: {values['max']}")
                print(f"\t\t- Минимум: {values['min']}")
                print(f"\t\t- всего значений: {values['count']}")
        if info["errors"]:
            print("\t[!] Ошибки найденные при обработке:")
            for error_type, error_values in info["errors"].items():
                if error_values:
                    print(f"\t\t- {error_type}: {len(error_values)} раз(а)")
                    for sample in error_values[:3]:
                        print(f"\t\t\tПример: {sample}")
    if report['global_errors']:
        print(f"\n{'=' * 3} ГЛОБАЛЬНЫЕ ОШИБКИ {'=' * 3}")
        for category, reasons in report['global_errors'].items():
            print(f"\n\t[{category}]")
            for reason, stat in reasons.items():
                print(f"\t\t{reason}: {stat['count']} раз(а)")
                for sample in stat["samples"]:
                    print(f"\t\t\tПример: {sample}")

def render_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)

def save_in_file(text: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text + '\n')

def read_file(file: str, top_n: int, log_type: str, time: str, output_format: str, out_file: str | None) -> None:

    if log_type == "nginx":
        parser_file = NginxParser(time)
    elif log_type == "syslog":
        parser_file = SyslogParser(time)
    elif log_type == "json":
        parser_file = JsonAppParser(time)
    elif log_type == "db":
        parser_file = DatabaseSlowQueryParser(time)
    else:
        print("Введен некоректный тип файла (nginx/syslog/json/db)")
        return
         
    with open(file, 'r', encoding='utf-8', errors='replace') as f:
        for i in f:
            parser_file.parser_log(i)
    
    if log_type == "db":
        parser_file.finalize()

    report = build_report(parser_file, top_n)

    if output_format == "json":
        text = render_json(report)
        path = out_file or f"out_file.{output_format}"
        save_in_file(text, path)
        print(f"Отчёт сохранён: {path}")
    else:
        display(report, parser_file.values_info)

def is_date(dataset: dict, obj: object, frmt: str, time: str, ip: str, type: str, flag=False) -> None:
    if dataset.get(type):
        date = dataset.pop(type)
        if flag:
            date = " ".join(date.split())
        try:
            dt = datetime.strptime(date, frmt)
            match time:
                case "Y":
                    date_str = dt.strftime("%Y")
                case "m":
                    date_str = dt.strftime("%Y-%m")
                case "d":
                    date_str = dt.strftime("%Y-%m-%d")
                case "M":
                    date_str = dt.strftime("%Y-%m-%d %H:%M")
                case "S":
                    date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                case _:
                    date_str = dt.strftime("%Y-%m-%d %H")
        except (ValueError, TypeError):
            obj.ip_analytics[ip].errors["date_parse_failed"].append(date)
            return    
        if date_str:
            obj.ip_analytics[ip].categorical[type].update([date_str])
            return
    obj.ip_analytics[ip].errors["date_parse_failed"].append("Отсутствует дата")

def is_match(match, obj: object, line: str) -> bool:
    if match:
        return True
    stripped = line.strip()
    if stripped and not stripped.startswith("#"):
        obj.global_errors["parsing"]["not_match"].add(line)
    else:
        obj.global_errors["parsing"]["blank_or_comment"].add(line)
    return False

def is_ip(dataset, obj: object) -> bool:
    if not isinstance(dataset, dict):
        obj.global_errors["not_ip"]["not_dict"].add(repr(dataset))
        return False
    ip = dataset.get("ip")
    if not isinstance(ip, str):
        obj.global_errors["not_ip"]["not_string"].add(repr(ip))
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        obj.global_errors["not_ip"]["incorrect"].add(ip)
        return False

def main() -> None:

    parser = argparse.ArgumentParser(description='Парсинг логов')

    parser.add_argument("-f", "--file", dest="file", required=True, help="Путь к файлу")
    parser.add_argument("-t", "--type", dest="type", required=True, choices=["nginx", "syslog", "json", "db"], help="Тип обрабатываемого файла")
    parser.add_argument("--time", dest="time", default="H", type=str, choices=["Y", "m", "d", "H", "M", "S"], help="Формат даты и времени")
    parser.add_argument("--top", dest="top_n", default=10, type=int, help="Количество строк")
    parser.add_argument("--output", dest="output_format", choices=["text", "json"], default="text", help="Формат для вывода")
    parser.add_argument("-o", "--out-file", dest="out_file", help="Путь для записи (иначе out.<format>)")

    args = parser.parse_args()

    file_path = Path(args.file)

    if not file_path.is_file():
        parser.error("Такого файла не существует")
    if args.top_n <= 0:
        parser.error("Количество строк должно быть больше 0")
    read_file(args.file, args.top_n, args.type, args.time, args.output_format, args.out_file)
        

if __name__=="__main__":
    main()
