import os
import re
import json
import time
import html
import argparse
import subprocess
import xml.etree.ElementTree as ET

from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Optional, Iterable
from concurrent.futures import ThreadPoolExecutor


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ZAP_PATH = "/usr/share/zaproxy/zap.sh"
# TODO CHANGE THE SCNR PATH
SCNR_PATH = "/home/kali/Desktop/Final/scnr-1.0dev-20231118_103208/scnr-1.0dev/bin/"


@dataclass(eq=True, frozen=True)
class VulnerabilityIssue:
    name: str
    risk_level: str

    url: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    reference: Optional[str] = None

    def __hash__(self):
        return hash((self.name, self.url))

    def __eq__(self, other):
        if not isinstance(other, VulnerabilityIssue):
            return NotImplemented
        return self.name == other.name and self.url == other.url


def extract_scnr_report_file_location_from_file(file_path: str) -> str:
    try:
        with open(file_path, "r") as file:
            text = file.read()
            pattern = r"Report saved at: ([^\s]+\.ser)"

            match = re.search(pattern, text)

            if match:
                return match.group(1)
            else:
                return "No file location found in the text."

    except FileNotFoundError:
        return "File not found."


def convert_ser_to_json(scnr_report_file_path: str) -> str:
    text = subprocess.check_output(
        f"bash {SCNR_PATH}scnr_reporter --report=json {scnr_report_file_path}",
        shell=True,
    ).decode("utf-8")

    match = re.search(r"(\b[\d-]+ \d+_\d+_\d+ -\d+)(\.json)", text)

    if match:
        return f"{match.group(1)}{match.group(2)}"
    else:
        print("No matching JSON file name found in the text.")


def parse_scnr_result(scnr_report_file_path: str) -> list:
    vulnerability_issues = []
    json_file_path = convert_ser_to_json(scnr_report_file_path)
    with open(json_file_path, "r") as file:
        data = json.load(file)

    for issue in data.get("issues", []):
        references = issue.get("references", {})
        refs = "".join([f"{ref}" for ref in references.values()])

        vulnerability_issue = VulnerabilityIssue(
            name=issue.get("name", "N/A"),
            risk_level=issue.get("severity", "N/A").capitalize(),
            url=issue.get("vector", {}).get("url", "N/A"),
            description=issue.get("description", "N/A"),
            solution=issue.get("remedy_guidance", "N/A").replace("\n", ""),
            reference=refs,
        )
        vulnerability_issues.append(vulnerability_issue)

    return vulnerability_issues


def is_valid_uri(uri: str) -> bool:
    result = urlparse(uri)
    return all([result.scheme, result.netloc])


def get_args() -> str:
    parser = argparse.ArgumentParser(
        description="Run scans on a specified target.",
    )

    parser.add_argument(
        "--target", type=str, required=True, help="The target URI for the scan"
    )

    args = parser.parse_args()

    if not is_valid_uri(args.target):
        parser.error("The target URI is invalid. Please enter a valid URI.")

    return args.target


def remove_file_if_exists(file_path: str) -> None:
    if os.path.exists(file_path):
        os.remove(file_path)


def strip_html_tags(text: str) -> str:
    clean = re.compile("<.*?>")
    return re.sub(clean, "", text)


def parse_zap_result(xml_file_path: str) -> list:
    vulnerability_issues = []
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    for alertitem in root.findall(".//alertitem"):
        uri = (
            alertitem.find(".//instance/uri").text
            if alertitem.find(".//instance/uri") is not None
            else "N/A"
        )

        vulnerability_issue = VulnerabilityIssue(
            name=alertitem.find("name").text,
            risk_level=alertitem.find("riskdesc").text,
            url=uri,
            description=strip_html_tags(
                html.unescape(alertitem.find("desc").text or "")
            ),
            solution=strip_html_tags(
                html.unescape(alertitem.find("solution").text or "")
            ),
            reference=strip_html_tags(
                html.unescape(alertitem.find("reference").text or "")
            ),
        )
        vulnerability_issues.append(vulnerability_issue)

    return vulnerability_issues


def initialize_file_state(output_file: str) -> dict:
    if os.path.exists(output_file):
        return {
            "last_size": os.path.getsize(output_file),
            "last_modified": os.path.getmtime(output_file),
        }
    else:
        return {"last_size": 0, "last_modified": 0}


def kill_zap() -> None:
    os.system("kill -9 $(ps aux | grep '[z]ap' | awk '{print $2}')")


def check_arachni_scan_status(report_path: str) -> list:
    if os.path.exists(report_path):
        file_state = initialize_file_state(report_path)

        while True:
            time.sleep(5)
            current_size = os.path.getsize(report_path)
            current_modified = os.path.getmtime(report_path)

            if (
                current_size == file_state["last_size"]
                and current_modified == file_state["last_modified"]
            ):
                print("Arachni scan complete, parsing ")
                break
            else:
                file_state["last_size"] = current_size
                file_state["last_modified"] = current_modified

        ser_file_path = extract_scnr_report_file_location_from_file(
            file_path=report_path
        )
        return parse_scnr_result(ser_file_path)


def run_zap_scan(
    target_uri: str, output_file: str, file_state: dict, index: int
) -> list:

    zap_command = (
        f"bash {ZAP_PATH} -daemon -quickprogress"
        f" -quickout {output_file}"
        f" -quickurl {target_uri}"
    )
    subprocess.Popen(zap_command, shell=True)

    while True:
        if os.path.exists(output_file):
            current_size = os.path.getsize(output_file)
            current_modified = os.path.getmtime(output_file)

            if (
                current_size == file_state["last_size"]
                and current_modified == file_state["last_modified"]
            ):
                print(f"ZAP Scan for {index} complete")
                break
            else:
                file_state["last_size"] = current_size
                file_state["last_modified"] = current_modified
        time.sleep(5)

    kill_zap()
    return parse_zap_result(
        xml_file_path=output_file,
    )


def run_scnr(target_uri: str, report_path: str) -> list:
    try:
        os.system(
            (
                f"bash {SCNR_PATH}scnr {target_uri}"
                f" --system-slots-override >> {report_path}"
            )
        )

        return check_arachni_scan_status(report_path)

    except FileNotFoundError:
        print("scnr is not found, edit the path")

    return []


def write_issue_to_file(
    issues: Iterable,
    file_path: str = "zap_scnr/output.txt",
):
    with open(file_path, "a") as file:
        for issue in issues:
            file.write(f"Vulnerability Name: {issue.name}\n")
            file.write(f"Risk Level: {issue.risk_level}\n")
            file.write(f"URL: {issue.url}\n")
            file.write(f"Description: {issue.description}\n")
            file.write(f"Solution: {issue.solution}\n")
            file.write(f"Reference: {issue.reference}\n")
            file.write("----------------------------------------\n")


def run_scans(target_uri: str, number_of_scans: int = 1) -> None:
    if not os.path.exists("zap_scnr"):
        os.mkdir("zap_scnr")

    if not os.path.exists(ZAP_PATH):
        raise FileNotFoundError("ZAP Does not exist")

    with ThreadPoolExecutor() as executor:
        for index in range(number_of_scans):
            zap_report_path = f"{SCRIPT_DIR}/zap_scnr/zapreport_{index}.xml"
            arachni_report_path = f"{SCRIPT_DIR}/zap_scnr/arachni_report_{index}.txt"

            remove_file_if_exists(zap_report_path)
            remove_file_if_exists(arachni_report_path)

            print(f"Starting scan {index} for {target_uri}")
            file_state = initialize_file_state(zap_report_path)

            zap_future = executor.submit(
                run_zap_scan,
                target_uri=target_uri,
                output_file=zap_report_path,
                file_state=file_state,
                index=index,
            )

            # scnr_future = executor.submit(
            #     run_scnr,
            #     target_uri=target_uri,
            #     report_path=arachni_report_path,
            # )

            zap_issues = zap_future.result()
            # scnr_issues = scnr_future.result()
            scnr_issues = []

            write_issue_to_file(set(scnr_issues + zap_issues))


if __name__ == "__main__":
    target = get_args()
    run_scans(target_uri=target, number_of_scans=1)
