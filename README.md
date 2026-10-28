# Decode and Interpret Security Logs

## Objective

The aim of this task is to take an authentication log, describe what normal activity looks like, find the events that do not fit, and explain which of them need further investigation and why. The full write-up, with screenshots, is in `FINDINGS.docx`.

## What is in this folder

| File | What it is |
|---|---|
| `FINDINGS.docx` | The main report: the log explained, the normal baseline, each finding, the limits of the analysis, screenshots and references |
| `generate_logs.py` | Creates the fictional log file `auth_logs.csv`. It uses a fixed random seed, so it gives the same data every time. All users are invented and all IP addresses come from the ranges reserved for documentation (RFC 5737) |
| `auth_logs.csv` | The dataset: 741 events from 19 to 25 October 2026, 25 accounts and 56 source IPs |
| `analyze_logs.py` | Works out the baseline and runs nine checks for suspicious behaviour |
| `test_analysis.py` | 13 tests that confirm the numbers in the report, that every planted attack is found, and that the harmless cases are not treated as attacks |
| `baseline.txt` | Summary of normal behaviour (output of `analyze_logs.py`) |
| `findings.csv` | One row per finding, with evidence and next step (output of `analyze_logs.py`) |
| `charts/` | Three charts made by `analyze_logs.py`: events by hour, failures by IP and daily events |

## Setup

You need Python 3.9 or newer. Install the two libraries once:

```
pip install pandas matplotlib
```

## How to run it

Open a terminal in this folder and run these three commands in order. On Windows you can use `python` instead of `python3`.

```
python3 generate_logs.py
python3 analyze_logs.py
python3 -m unittest -v test_analysis.py
```

The first command writes `auth_logs.csv`. The second prints the baseline and the findings, and writes `baseline.txt`, `findings.csv` and the charts. The third runs the tests and should finish with `Ran 13 tests` and `OK`.

## The log format

Each row has seven fields: `timestamp`, `user`, `src_ip`, `country`, `event`, `user_agent` and `reason`. The event types are `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `MFA_DENIED`, `ACCOUNT_LOCKED`, `PASSWORD_CHANGE` and `PRIV_GRANT`. Section 2 of the report explains each field with an example.

## How the analysis works

First I measure normal behaviour: working hours, home country, browsers, the usual failure rate, and the addresses and browser each user normally has. Then nine checks compare every event against that picture. They look for brute force, password spraying, impossible travel, repeated denied MFA approvals, service accounts used like people, unusual client software, off-hours logins, account lockouts and new privileged accounts. For each result the report gives the evidence, other explanations I considered, and what to do next. I left two harmless events in the data on purpose (a lockout and an on-call login) to show that not everything unusual is an attack.

## Test results

I ran `python -m unittest -v test_analysis` on my own Windows laptop and all 13 tests passed. The screenshots are in section 9 of `FINDINGS.docx`.

- 3 tests check the numbers quoted in the report: 741 events, 198 failures, 175 of them from two addresses, 143 uses of python-requests with 142 from one address, and the 4.2% normal failure rate.
- 7 tests check that each planted attack is detected: brute force, the new admin account, password spraying, impossible travel, MFA fatigue, the misused service account and the scripted client.
- 3 tests check that the two harmless cases (`jroy` and `mkhan`) stay low priority, that eight normal users have no findings, and that there are exactly 12 rows in `findings.csv`.

## Results in short

The log contains three critical incidents (a brute force attack on `admin` followed by a new admin account, and password spraying that got into `dpatel`), three high ones (denied approval spam against `tnair`, impossible travel for `asharma` and a misused backup service account), one medium, one low and one informational. `findings.csv` has 12 rows while the report's summary table has 9, because the impossible travel check fires three separate times for two users, and the report groups those with their main incident.

## Limits

The data is made up and the attacks were planted, so this shows the method works but not that it would be this clean on a real log. Country checks are rough, the thresholds were my own choices and would need tuning, and a login log cannot show what an attacker did after getting in. These points are covered in section 7 of the report.
