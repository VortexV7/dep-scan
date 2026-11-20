# Sample app: pyyaml is imported AND called (reachable), flask is listed
# in requirements.txt but never imported anywhere (unreachable).
import yaml


def load_config(text):
    return yaml.safe_load(text)


if __name__ == "__main__":
    print(load_config("name: depscan\nversion: 1\n"))
