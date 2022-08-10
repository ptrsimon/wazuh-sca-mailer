#!/usr/bin/python3
#
# wazuh-sca-mailer.py - get system configuration status from Wazuh API and send them as CSV
#

import datetime
import argparse
import requests
import json
import sys
import smtplib
import mimetypes
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def parse_args():
    parser = argparse.ArgumentParser(
        description="Get system configuration status from Wazuh API and send them as CSV")
    parser.add_argument("-c", dest="config", type=str, help="config file location (default: /etc/wazuh-sca-mailer/wazuh-sca-mailer.conf)",
                        default="/etc/wazuh-sca-mailer/wazuh-sca-mailer.conf")
    parser.add_argument("-l", dest="logfile", type=str,
                        help="log file location (default: /var/log/wazuh-sca-mailer.log)",
                        default="/var/log/wazuh-sca-mailer.log")
    parser.add_argument("-s", action="store_true", help="silent mode - no output")

    return parser.parse_args()

def log_msg(msg: str, logfile: str, level: str, silent: bool):
    if not silent:
        print(msg)

    try:
        fh = open(logfile, 'a')
    except OSError:
        print("Failed to open logfile: " + logfile)
        sys.exit(1)

    with fh:
        fh.write("{} {} {}".format(
            datetime.datetime.now().isoformat(),
            level,
            msg + "\n"))

def read_config(path: str, logpath: str, silent: bool):
    config = {}
    try:
        with open(path, "r") as fh:
            config = json.load(fh)
    except Exception as e:
        log_msg("Failed to read config: " + str(e), logpath, "ERROR", silent)
        sys.exit(1)

    return config

def get_token(url: str, user: str, pw: str, logpath: str, silent: bool):
    authurl = url + "/security/user/authenticate/"
    resp = requests.get(authurl, auth=(user, pw))
    if (resp.status_code != 200):
        log_msg("Failed to get auth token from " + authurl + ". Status code: " + str(resp.status_code),
                logpath, "ERROR", silent)
        sys.exit(1)

    return json.loads(resp.text)["data"]["token"]

def get_agents(url: str, token: str, pattern: str, logpath: str, silent: bool):
    agents = []
    agenturl = url + "/agents"
    patternre = re.compile(pattern)
    resp = requests.get(agenturl, params={"limit": 100000, "select": "id,name"},
        headers={"Authorization": "Bearer " + token})
    if (resp.status_code != 200):
        log_msg("Failed to get agents from " + agenturl + ". Status code: " + str(resp.status_code),
                logpath, "ERROR", silent)
        sys.exit(1)

    for i in json.loads(resp.text)["data"]["affected_items"]:
        if patternre.search(i["name"]):
            agents.append({"id": i["id"], "name": i["name"]})

    return agents

def get_agent_sca_summary(url: str, token: str, agent_id: int, policy_ids, logpath: str, silent: bool):
    sca_summaries = []
    for i in policy_ids:
        sumurl = url + "/sca/" + str(agent_id)
        resp = requests.get(sumurl, headers={"Authorization": "Bearer " + token}, params={"q": "policy_id=" + i})
        if resp.status_code != 200:
            log_msg("Failed to get system config check summaries from " + sumurl + ". Status code: " + str(resp.status_code),
                    logpath, "ERROR", silent)

        respobj = json.loads(resp.text)
        if "data" in respobj:
            for j in json.loads(resp.text)["data"]["affected_items"]:
                sca_summaries.append(
                    {
                        "policy_id": i,
                        "pass": j["pass"],
                        "fail": j["fail"],
                        "score": j["score"]
                    }
                )
    
    return sca_summaries

def get_agent_scas(url: str, token: str, agent_id: int, policy_ids, logpath: str, silent: bool):
    scas = []
    for i in policy_ids:
        scaurl = url + "/sca/" + str(agent_id) + "/checks/" + str(i)
        resp = requests.get(scaurl, headers={"Authorization": "Bearer " + token}, params={"result": "failed"})
        if resp.status_code != 200:
            log_msg("Failed to get system config checks from " + scaurl + ". Status code: " + str(resp.status_code),
                    logpath, "ERROR", silent)

        respobj = json.loads(resp.text)
        if "data" in respobj:
            for j in respobj["data"]["affected_items"]:
                scas.append(
                    {
                        "title": j["title"],
                        "result": j["result"],
                        "remediation": j["remediation"] if "remediation" in j else "unknown"
                    }
                )
    
    return scas

def render_csv(scas):
    csvstr = ""
    for k, v in scas.items():
        if v:
            for j in v:
                csvstr += k + "," + j["title"] + "," + j["result"] + "," + j["remediation"] + "\n"

    if csvstr == "":
        return None
    else:
        return csvstr

def render_sum_csv(sca_summaries):
    csvstr = ""

    for k, v in sca_summaries.items():
        if k and v:
            for i in v:
                csvstr += k + "," + i["policy_id"] + ","
                csvstr += str(i["pass"]) + ","
                csvstr += str(i["fail"]) + ","
                csvstr += str(i["score"]) + "%\n"

    if csvstr == "":
        return None
    else:
        return "hostname,policy,pass,fail,score\n" + csvstr

def send_mail(sca_csv: str, sca_summary_csv: str, smtp_host: str, smtp_port: int,
        mail_from: str, mail_to, mail_subject: str,
        config_policy_ids, config_hostfilter,
        logpath: str, silent: bool):

    datestr = datetime.datetime.now().strftime("%Y-%m-%d")
    timestr = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    message = MIMEMultipart()
    message["subject"] = mail_subject
    message["From"] = mail_from
    message["To"] = ','.join(mail_to)

    if sca_csv is not None:
        bodytext = "Lines in CSV: " + str(len(sca_csv.split("\n"))) + "\n"
    else:
        bodytext = "No system configuration checks found.\n"

    bodytext += "\nSettings\n"
    bodytext += "hostfilter: " + config_hostfilter + "\n"
    bodytext += "policies: " + ','.join(config_policy_ids) + "\n\n"
    bodytext += "Generated by wazuh-sca-mailer.py at " + timestr + "\n\n"
    body = MIMEText(bodytext)

    message.attach(body)

    if sca_csv is not None:
        attachment = MIMEText(sca_csv)
        attachment.add_header("Content-Disposition", "attachment", filename="sca-" + datestr + ".csv")
        message.attach(attachment)

    if sca_summary_csv is not None:
        attachment = MIMEText(sca_summary_csv)
        attachment.add_header("Content-Disposition", "attachment", filename="scasummary-" + datestr + ".csv")
        message.attach(attachment)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as sh:
            sh.sendmail(mail_from, mail_to, message.as_string())
    except Exception as e:
        log_msg("Failed to send mail: " + str(e), logpath, "ERROR", silent)
        return

    log_msg("Sent mail for target: to=" + ','.join(mail_to) +
            ";hostfilter=" + config_hostfilter +
            ";policy_ids=" + ','.join(config_policy_ids),
            logpath, "INFO", silent)

def main():
    args = parse_args()
    config = read_config(args.config, args.logfile, args.s)
    token = get_token(config["wazuh"]["url"],
            config["wazuh"]["user"], config["wazuh"]["pw"], args.logfile, args.s)

    for i in config["targets"]:
        scas = {}
        sca_summaries = {}
        for j in get_agents(config["wazuh"]["url"], token, i["sca"]["hostfilter"], args.logfile, args.s):
            scas[j["name"]] = get_agent_scas(config["wazuh"]["url"], token, j["id"],
                              i["sca"]["policy_ids"], args.logfile, args.s)
            sca_summaries[j["name"]] = get_agent_sca_summary(config["wazuh"]["url"], token, j["id"],
                              i["sca"]["policy_ids"], args.logfile, args.s)

        send_mail(render_csv(scas), render_sum_csv(sca_summaries), config["smtp"]["host"], config["smtp"]["port"],
                  i["mail"]["from"], i["mail"]["to"], i["mail"]["subject"],
                  i["sca"]["policy_ids"], i["sca"]["hostfilter"],
                  args.logfile, args.s)

    sys.exit(0)

if __name__ == "__main__":
    main()
