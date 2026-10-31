"""Extract matching APKM/XAPK inputs without trusting archive paths."""
import json
from pathlib import Path
import shutil
import zipfile

from games import ABIS, select_abi


def extract_bundle(path, work, abi=None):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('duplicate bundle ZIP entry')
        if 'info.json' in names:
            metadata = json.loads(archive.read('info.json'))
            package = metadata.get('pname', '')
            base, prefix, assets = 'base.apk', 'split_config.', 'split_install_time_asset_pack.apk'
        elif 'manifest.json' in names:
            metadata = json.loads(archive.read('manifest.json'))
            package = metadata.get('package_name', '')
            base, prefix, assets = str(package) + '.apk', 'config.', 'install_time_asset_pack.apk'
        else:
            raise ValueError('expected APKM info.json or XAPK manifest.json')
        if not isinstance(package, str) or not package or '/' in package or '\\' in package:
            raise ValueError('bundle has an invalid package name')
        available = {a for a in ABIS if any(
            Path(n).name == prefix + a.replace('-', '_') + '.apk' for n in names)}
        abi = select_abi(available, abi)
        basenames = (base, prefix + abi.replace('-', '_') + '.apk', assets)

        def extract(basename):
            matches = [n for n in names if Path(n).name == basename]
            if len(matches) != 1:
                raise ValueError('bundle must contain exactly one ' + basename)
            dest = work / basename
            with archive.open(matches[0]) as source, dest.open('xb') as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
            return dest

        result = dict(zip(('base', 'native_split', 'asset_pack'), map(extract, basenames)))
        # Native and asset splits are handled separately. All other configuration
        # APKs (including languages, not just density) contain resource tables.
        configs = []
        for name in names:
            basename = Path(name).name
            if basename.startswith(('config.', 'split_config.')) and basename.endswith('.apk'):
                if basename in basenames or any(
                        basename in ('config.' + a.replace('-', '_') + '.apk',
                                     'split_config.' + a.replace('-', '_') + '.apk') for a in ABIS):
                    continue
                configs.append(extract(basename))
        result['resource_split'] = configs
        result['abi'] = abi
        return result
