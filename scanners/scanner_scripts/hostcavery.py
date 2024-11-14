import subprocess
import re


def run_dnsenum_and_save_cleaned(domain: str, output_file: str) -> None:
    try:
        print(f"Running dnsenum for {domain}")
        dnsenum_command = f"dnsenum {domain}"

        try:
            completed_process = subprocess.run(
                dnsenum_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            output = completed_process.stdout
        except subprocess.TimeoutExpired as timeout_error:
            print(f"Process timed out: {timeout_error}")
            output = (
                timeout_error.stdout.decode("utf-8") if timeout_error.stdout else ""
            )

        cleaned_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
        cleaned_output = re.sub(
            r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]", "", cleaned_output
        )

        with open(output_file, "a") as result_file:
            result_file.write(f"Results for {domain} (DNSEnum):\n")
            result_file.write(cleaned_output)
            result_file.write("\n")

        print(f"DNSEnum results saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running dnsenum: {e}")


def run_whois_and_save(domain, output_file):
    try:
        completed_process = subprocess.run(
            f"whois {domain}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = completed_process.stdout

        with open(output_file, "a") as result_file:
            result_file.write(f"Results for {domain} (WHOIS):\n")
            result_file.write(output)
            result_file.write("\n")

        print(f"WHOIS results saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running whois: {e}")


def exceute_whois_dns_scans(domain: str, output_file: str) -> None:
    if "//" in domain:
        domain = domain.split("//")[1]
    run_whois_and_save(domain, output_file)
    run_dnsenum_and_save_cleaned(domain, output_file)


if __name__ == "__main__":
    domain = input("Enter target domain (eg: example.com): ")
    output_file = "whois_dns_results.txt"
    exceute_whois_dns_scans(domain, output_file)
