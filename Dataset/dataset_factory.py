from Dataset.dataset_nvd import NvdDataset
from Dataset.dataset_samate import SamateDataset


def get_dataset(ds):
    if ds.lower() == 'samate':
        ds = SamateDataset()
        ds.create_sets()

        return ds
    elif ds.lower() == 'nvd':
        ds = NvdDataset()
        ds.create_sets()

        return ds
    else:
        return None

