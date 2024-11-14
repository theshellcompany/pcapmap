# pcapmap
Generating a quick and dirty graph from a pcap.

## Example use

At [malware traffic analysis](https://www.malware-traffic-analysis.net/2024/10/23/index.html) you can get the `2024-10-23-Redline-Stealer-infection-traffic.pcap`

```shell
python -m venv
source ./venv/bin/activate
pip install -r requirements.txt
python pcapmap.py 2024-10-23-Redline-Stealer-infection-traffic.pcap
```

This will produce you a graph giving you a basic idea of the pcap.
