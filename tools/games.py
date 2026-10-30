"""Explicitly supported Supercell ARM64 shield names."""
GAMES = {
    'com.supercell.brawlstars': 'supercell_brawlstars',
    'com.supercell.clashofclans': 'supercell_clashofclans',
    'com.supercell.clashroyale': 'supercell_clashroyale',
    'com.supercell.moco': 'supercell_moco',
    'com.supercell.squad': 'supercell_squad',
    'com.supercell.hayday': 'supercell_hayday',
    'com.supercell.boombeach': 'supercell_boombeach',
}
SHIELDS = {'lib/arm64-v8a/lib' + name + '.so' for name in GAMES.values()}


def shield_for(package):
    try:
        return 'lib/arm64-v8a/lib' + GAMES[package] + '.so'
    except KeyError:
        raise ValueError('unsupported game package: ' + str(package)) from None
