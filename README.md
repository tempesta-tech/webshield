# Tempesta WebShield

Automatic detection and blocking bad bots (DDoS, shopping bots, scrappers,
booking bots and others) by TLS and HTTP fingerprints or IP based on Tempesta FW
access logs stored in the Clickhouse database.

*The current version 0.1 is experimental and should not be used in production.*

## Wiki
* [How it works](https://tempesta-tech.com/knowledge-base/Bot-Protection/#how-it-works)
* [Installation and quick start](https://tempesta-tech.com/knowledge-base/Bot-Protection/#quick-start)
* [Configuration](https://tempesta-tech.com/knowledge-base/Bot-Protection/#historical-mode)
* [Use cases](https://tempesta-tech.com/knowledge-base/Bot-Protection/#how-to-defend-your-app)


## Requirements

- Python 3.12 <=
- [Tempesta FW](https://github.com/tempesta-tech/tempesta) 0.8.0 <=
- Clickhouse 25.6.0 <=

## Install

```bash
git clone https://github.com/tempesta-tech/webshield.git
cd webshield
sudo setup.sh
```

## Prepare
Before running the application, you need to prepare Tempesta FW:

1. Configure Tempesta Logger 
   (https://tempesta-tech.com/knowledge-base/Handling-clients/#access-log and https://tempesta-tech.com/knowledge-base/).
2. Modify your Tempesta FW configuration and add the `tfh` and `tft` include directories.(https://tempesta-tech.com/knowledge-base/Bot-Protection/#3-add-blocking-rule-sets-to-tempesta-fw-configuration-file)
3. Start Tempesta FW with Tempesta Logger enabled
4. Start ClickHouse DB and ensure the `access_log` table exists.

## Run

```bash
systemctl start tempesta-webshield.service
```

## See logs

```bash
journalctl -f -u tempesta-webshield
```

## Run tests

To run the tests you need to copy GeoLite2-City.mmdb to `tests/` directory.

```bash
# run all tests with a logging level INFO
pytest

```

## Format project
```bash
black .
isort .
```
