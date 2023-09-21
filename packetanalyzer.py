import os
import subprocess
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import smtplib
from email.mime.text import MIMEText
import logging
import argparse
import numpy as np
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

logging.basicConfig(filename='packet_analysis.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')


parser = argparse.ArgumentParser(description='Packet capture and analysis.')
parser.add_argument('--interface', default='en0',
                    help='Network interface to capture on.')
parser.add_argument('--count', default='50',
                    help='Number of packets to capture.')
args = parser.parse_args()

username = os.getenv('SMTP_USERNAME')
password = os.getenv('SMTP_PASSWORD')
smtp_server = os.getenv('SMTP_SERVER')
smtp_port = os.getenv('SMTP_PORT')


def send_email(subject: str, message: str) -> None:
    try:
        from_email = "example@outlook.com"
        to_email = "example@gmail.com"

        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()

        # Log in and send mail without checking is_secure
        server.login(username, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


def capture_packets(interface: str, count: str) -> str:
    filename = f'temp_output_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap'
    try:
        subprocess.run(["tshark", "-i", interface, "-c",
                       str(count), "-w", filename], check=True)
        logging.info(f"Captured {count} packets on interface {interface}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to capture packets: {e}")
        raise
    return filename  # Return the filename for further processing


def analyze_packets(filename: str) -> None:
    try:
        process = subprocess.run(["tshark", "-r", filename, "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e",
                                  "tcp.dstport", "-e", "tcp.flags", "-E", "separator=\t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if process.returncode != 0:
            logging.error(f"Failed to analyze packets: {process.stderr}")
            raise RuntimeError(f"tshark command failed: {process.stderr}")
        with open("analyzed_output.txt", "w") as f:
            f.write(process.stdout)

        logging.info("Packet analysis complete.")
    except Exception as e:
        logging.error(f"Failed to analyze packets: {e}")
        raise


def read_and_parse_file(filename: str):
    src_ips, dst_ips, tcp_dstports, tcp_flags = [], [], [], []
    with open(filename, "r") as file:
        lines = file.readlines()

    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            logging.info("Skipping empty line")
            continue

        fields = stripped_line.split("\t")
        if len(fields) < 2:  # Modified this line to require at least 2 fields.
            logging.warning(f"Skipping invalid line: {stripped_line}")
            continue

        # Extract the first two fields as src and dst IPs.
        src, dst = fields[:2]
        src_ips.append(src)
        dst_ips.append(dst)

        # If there are more fields, extract them, else use default values.
        port = fields[2] if len(fields) > 2 else "N/A"
        flags = fields[3] if len(fields) > 3 else "N/A"
        tcp_dstports.append(port)
        tcp_flags.append(flags)

    return Counter(src_ips), Counter(dst_ips), Counter(tcp_dstports), Counter(tcp_flags)


def dynamic_threshold(counter: Counter, sensitivity: float = 1.0) -> float:
    values = list(counter.values())
    if not values:
        logging.warning("No values to calculate the threshold.")
        return 0

    mean = np.mean(values)
    std_dev = np.std(values)
    threshold = mean + (sensitivity * std_dev)
    return threshold


def check_activity(ip_counter: Counter, type_ip: str) -> None:
    threshold = dynamic_threshold(ip_counter)
    for ip, count in ip_counter.items():
        if count > threshold:
            message = f"Suspicious {type_ip} IP {ip} has been detected {count} times."
            send_email(f"Suspicious {type_ip} IP Detected", message)
            logging.info(message)


def detect_ddos(src_ip_counter: Counter, tcp_flags_counter: Counter) -> None:
    # Sum the count of SYN packets from the tcp_flags_counter
    syn_count = sum(
        count for flag, count in tcp_flags_counter.items() if flag == '0x0002')
    # Sum the count of ACK packets from the tcp_flags_counter
    ack_count = sum(
        count for flag, count in tcp_flags_counter.items() if flag == '0x0010')

    logging.info(f"SYN Count: {syn_count}, ACK Count: {ack_count}")

    if ack_count == 0:
        syn_ack_ratio = float('inf')
        message = "Potential DDoS attack detected. The SYN/ACK ratio is infinity due to no ACK packets received."
    else:
        syn_ack_ratio = syn_count / ack_count
        message = f"Potential DDoS attack detected. SYN/ACK ratio: {syn_ack_ratio:.2f}."

    # Define a threshold ratio for detection of DDoS attacks
    # Arbitrary value; should be adjusted according to normal network behavior
    threshold_ratio = 1.0

    # If the calculated SYN/ACK ratio exceeds the threshold, send an alert email and log the message
    if syn_ack_ratio > threshold_ratio:
        send_email("Potential DDoS Attack Detected", message)
        logging.info(message)


def visualize_data(src_counter: Counter, dst_counter: Counter) -> None:
    fig, axs = plt.subplots(2, 1, figsize=(10, 8))

    # Sort and visualize Source IPs
    src_items = sorted(src_counter.items(), key=lambda x: x[1], reverse=True)
    src_keys, src_values = zip(*src_items)
    axs[0].barh(src_keys, src_values, color='b', alpha=0.7)
    axs[0].set_title('Source IPs')
    axs[0].set_xlabel('Count')
    axs[0].invert_yaxis()  # To display the highest value at the top
    for i, v in enumerate(src_values):
        axs[0].text(v, i, str(v), color='b', va='center')

    # Sort and visualize Destination IPs
    dst_items = sorted(dst_counter.items(), key=lambda x: x[1], reverse=True)
    dst_keys, dst_values = zip(*dst_items)
    axs[1].barh(dst_keys, dst_values, color='r', alpha=0.7)
    axs[1].set_title('Destination IPs')
    axs[1].set_xlabel('Count')
    axs[1].invert_yaxis()  # To display the highest value at the top
    for i, v in enumerate(dst_values):
        axs[1].text(v, i, str(v), color='r', va='center')

    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    try:
        filename = capture_packets(args.interface, args.count)
        analyze_packets(filename)

        src_ip_counter, dst_ip_counter, tcp_dstports_counter, tcp_flags_counter = read_and_parse_file(
            "analyzed_output.txt")
        check_activity(src_ip_counter, 'Source')
        check_activity(dst_ip_counter, 'Destination')
        detect_ddos(src_ip_counter, tcp_flags_counter)
        visualize_data(src_ip_counter, dst_ip_counter)
    finally:
        if os.path.exists("analyzed_output.txt"):
            os.remove("analyzed_output.txt")
            logging.info("Removed temporary analysis text file.")
        # Ensure filename is not None before
        if filename and os.path.exists(filename):
            os.remove(filename)
            logging.info("Removed temporary pcap file.")
