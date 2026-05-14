import subprocess

def lookip(ip):
    try:
        result = subprocess.check_output(
            ["geoiplookup", ip],
            text=True
        ).strip()

        return result

    except Exception:

        return "Unknown"