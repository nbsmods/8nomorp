"""Supercell shield paths for the supported Android ARM ABIs."""
ABIS = ('arm64-v8a', 'armeabi-v7a')
GAMES = {
    'com.supercell.brawlstars': 'supercell_brawlstars',
    'com.supercell.clashofclans': 'supercell_clashofclans',
    'com.supercell.clashroyale': 'supercell_clashroyale',
    'com.supercell.moco': 'supercell_moco',
    'com.supercell.squad': 'supercell_squad',
    'com.supercell.hayday': 'supercell_hayday',
    'com.supercell.boombeach': 'supercell_boombeach',
}
SHIELDS = {'lib/' + abi + '/lib' + name + '.so'
           for abi in ABIS for name in GAMES.values()}


def select_abi(available, requested=None):
    if requested is not None and requested not in ABIS:
        raise ValueError('unsupported Android ABI: ' + str(requested))
    choices = (requested,) if requested else ABIS
    for abi in choices:
        if abi in available:
            return abi
    raise ValueError('no matching native split for ' + (requested or 'ARM64/ARM32'))


def shield_for(package, abi='arm64-v8a'):
    if abi not in ABIS:
        raise ValueError('unsupported Android ABI: ' + str(abi))
    try:
        return 'lib/' + abi + '/lib' + GAMES[package] + '.so'
    except KeyError:
        raise ValueError('unsupported game package: ' + str(package)) from None
