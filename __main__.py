from Utils.logs import *
from Utils.config import *
from Dataset.dataset_nvd import NvdDataset


def cmd_create_model():
    print_banner("Building sets")
    ds = NvdDataset()

    ds.create_sets()


def main():
    init()
    cmd_create_model()


if __name__ == "__main__":
    main()
