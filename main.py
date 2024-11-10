import os
import sys
import vdf
import json
import struct
import logging
import argparse
from pathlib import Path
from binascii import crc32
from steam.webauth import WebAuth
from steam.client import SteamClient
from steam.client.cdn import CDNClient, CDNDepotManifest
from steam.enums import EResult, EBillingType
from steam.protobufs.content_manifest_pb2 import ContentManifestSignature

def get_exe_dir():
    # https://pyinstaller.org/en/stable/runtime-information.html
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

def dmg_save_manifest(manifest: CDNDepotManifest, depot_key: bytes,
                      remove_old=False, save_path=None):
    app_id = int(manifest.app_id)
    depot_id = str(manifest.depot_id)
    manifest_gid = str(manifest.gid)
    if not save_path:
        save_path = Path().absolute()
    app_path = save_path / f'depots/{app_id}'
    manifest_path = app_path / f'{depot_id}_{manifest_gid}.manifest'
    if manifest_path.exists():
        return True, manifest_path, []
    log.info("app_id: %s | depot_id: %s | manifest_gid: %s | DecryptionKey: %s",
             app_id, depot_id, manifest_gid, depot_key.hex())
    manifest.decrypt_filenames(depot_key)
    manifest.signature = ContentManifestSignature()
    for mapping in manifest.payload.mappings:
        mapping.filename = mapping.filename.rstrip('\x00 \n\t')
        mapping.chunks.sort(key=lambda x: x.sha)
    manifest.payload.mappings.sort(key=lambda x: x.filename.upper())
    if not os.path.exists(app_path):
        os.makedirs(app_path)
    if os.path.isfile(app_path / 'config.vdf'):
        with open(app_path / 'config.vdf') as f:
            d = vdf.load(f)
    else:
        d = vdf.VDFDict({'depots': {}})
    d['depots'][depot_id] = {'DecryptionKey': depot_key.hex()}
    d = {'depots': dict(sorted(d['depots'].items()))}
    delete_list = []
    if remove_old:
        for file in app_path.iterdir():
            if file.suffix == '.manifest':
                depot_id_, manifest_gid_ = file.stem.split('_')
                if depot_id_ == str(depot_id) and manifest_gid_ != str(manifest_gid):
                    file.unlink(missing_ok=True)
                    delete_list.append(file.name)
    buffer = manifest.payload.SerializeToString()
    manifest.metadata.crc_clear = crc32(struct.pack('<I', len(buffer)) + buffer)
    with open(manifest_path, 'wb') as f:
        f.write(manifest.serialize(compress=False))
    with open(app_path / 'config.vdf', 'w') as f:
        vdf.dump(d, f, pretty=True)
    return True, manifest_path, delete_list

def dmg_filter_func(depot_id: int, depot_info: dict):
    if depot_info.get('sharedinstall') == '1' and not args.shared_install:
        return False # skip sharedinstalls
    return True


parser = argparse.ArgumentParser()
parser.add_argument(
    '-u', '--username', required=False, default='',
    help='optional when credential present')
parser.add_argument(
    '-p', '--password', required=False, default='',
    help='optional when credential present')
parser.add_argument(
    '-l', '--login-id', required=False, default=None)

parser.add_argument(
    '-C', '--credential-file', required=False,
    default=os.path.join(get_exe_dir(), 'refresh_tokens.json'),
    help='file for read/write the credential tokens')
parser.add_argument(
    '-a', '--app-id', required=False,
    help='only download manifest owned by selected appids e.g. 480,730')
parser.add_argument(
    '-i', '--only-info', action='store_true', required=False,
    help='only list appid info owned by logged-on user and exit')
parser.add_argument(
    '-s', '--shared-install', action='store_true', required=False,
    help='download sharedinstall manifest, default not')
parser.add_argument(
    '-r', '--remove-old', action='store_true', required=False,
    help='remove old manifest on update')
parser.add_argument(
    '-o', '--save-path', required=False,
    help='where to save the manifest')

levellist = ''
for l in logging.getLevelNamesMapping(): 
    levellist += f'{l} '
parser.add_argument(
    '-L', '--logging-level', required=False, default='INFO',
    help=levellist)
args = parser.parse_args()

log = logging.getLogger(__name__)
logging.basicConfig(level=args.logging_level,
    format='%(asctime)s - %(levelname)s | %(message)s')

USERNAME, PASSWORD = args.username, args.password

# load credentials
refresh_tokens = {}
if os.path.isfile(args.credential_file):
    with open(args.credential_file) as f:
        try:
            lf = json.load(f)
            if isinstance(lf, dict):
                refresh_tokens = lf
        except:
            pass

# select username from credentials if not already persent
if not USERNAME:
    users = {i: user for i, user in enumerate(refresh_tokens, 1)}
    if len(users) != 0:
        for i, user in users.items():
            print(f"{i}: {user}")
        while True:
            try:
                num=int(input("Choose an account to login (0 for add account): "))
            except ValueError:
                print('Please type a number'); continue
            break
        USERNAME = users.get(num)

# still no username? ask user
if not USERNAME:
    USERNAME = input("Steam user: ")

REFRESH_TOKEN = refresh_tokens.get(USERNAME)

if not REFRESH_TOKEN:
    auth = WebAuth()
    try:
        auth.cli_login(USERNAME, PASSWORD)
        REFRESH_TOKEN = auth.refresh_token
        with open(args.credential_file, 'w') as f:
            refresh_tokens.update({USERNAME: REFRESH_TOKEN})
            json.dump(refresh_tokens, f, indent=4)
    except Exception as e:
        log.error(f'Unknown exception: {e}')
        exit(1)

client = SteamClient()
result = client.login(USERNAME, PASSWORD, REFRESH_TOKEN, args.login_id)
if result != EResult.OK:
    log.error(f'Login failure reason: {result.__repr__()}')
    exit(result)

if not client.licenses:
    log.error("No steam licenses found on SteamClient instance")
    exit(1)

app_id_list = []
if args.app_id:
    app_id_list = {int(app_id) for app_id in args.app_id.split(',')}
else:
    # only query paid appid
    paidtype_list = [
        EBillingType.BillOnceOnly,
        EBillingType.BillMonthly,
        EBillingType.BillOnceOrCDKey,
        EBillingType.Repurchaseable,
        EBillingType.Rental,
        EBillingType.ProofOfPrepurchaseOnly,
        EBillingType.Gift]
    packages = list(map(lambda l: {'packageid': l.package_id, 'access_token': l.access_token},
                        client.licenses.values()))
    for package_id, info in client.get_product_info(packages=packages)['packages'].items():
        if 'appids' in info and 'depotids' in info and info['billingtype'] in paidtype_list:
            app_id_list.extend(list(info['appids'].values()))

if len(app_id_list) == 0:
    log.error('No app found')
    exit(1)

if args.only_info:
    fresh_resp = client.get_product_info(app_id_list)
    for app_id in app_id_list:
        app = fresh_resp['apps'][app_id]
        log.info("%s | %s | %s", app_id, app['common']['type'].upper(), app['common']['name'])
        exit()

cdn = CDNClient(client)
for app_id in app_id_list:
    if not int(app_id) in {*cdn.licensed_depot_ids, *cdn.licensed_app_ids}:
        log.warning(f"account '{USERNAME}' not owned '{app_id}', ignored")
        continue
    for manifest in cdn.get_manifests(app_id, filter_func=dmg_filter_func):
        depot_key = cdn.get_depot_key(manifest.app_id, manifest.depot_id)
        dmg_save_manifest(manifest, depot_key, args.remove_old, args.save_path)

client.logout()
log.info('done!')