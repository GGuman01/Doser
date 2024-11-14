import os
import time
import subprocess

# from .ddoser import get_args


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NUCLEI_TEMPLATES_LOCATION = "/home/kali/.local/nuclei-templates"


def remove_file_if_exists(file_path: str) -> None:
    if os.path.exists(file_path):
        os.remove(file_path)


def initialize_file_state(output_file: str) -> dict:
    if os.path.exists(output_file):
        return {
            "last_size": os.path.getsize(output_file),
            "last_modified": os.path.getmtime(output_file),
        }
    else:
        return {"last_size": 0, "last_modified": 0}


def parse_and_write_nuclei_output(
    report_path: str,
    output_file_path: str = "nuclei_results/nuclei_result.txt",
) -> None:
    with open(report_path, "r") as infile, open(
        output_file_path,
        "w",
    ) as outfile:
        for line in infile:
            parts = line.strip().split(" ")

            if len(parts) >= 4:
                formatted_entry = (
                    f"Vulnerability Name: {parts[0].strip('[]')}\n"
                    f"Protocol: {parts[1].strip('[]')}\n"
                    f"Risk Level/Severity: {parts[2].strip('[]')}\n"
                    f"URL: {parts[3]}\n"
                    "----------------------------------------\n"
                )
                outfile.write(str(formatted_entry) + "\n")

    print(f"Report saved on {output_file_path}")


def run_nuclei_scan(target_uri: str, report_path: str) -> None:
    if not os.path.exists("nuclei_results"):
        os.mkdir("nuclei_results")

    report_path = f"nuclei_results/{report_path}"

    process = subprocess.Popen(
        [
            "nuclei",
            "-t",
            NUCLEI_TEMPLATES_LOCATION,
            "-u",
            target_uri,
            "-o",
            report_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    while True:
        if process.poll() is not None:
            print("Process finished.")
            break
        else:
            print("Ongoing nuclei scan")
            time.sleep(15)

    parse_and_write_nuclei_output(report_path=report_path)


# if __name__ == "__main__":
#     # target = get_args()
#     run_nuclei_scan(
#         target_uri=target,
#         report_path="nuclei_results/nuclei_report_0.txt",
#     )
