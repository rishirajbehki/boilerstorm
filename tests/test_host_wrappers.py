import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]


class HostWrapperTests(unittest.TestCase):
    def test_windows_first_run_and_explicit_modes(self):
        fake = '''param([string]$ExpectedHost,[switch]$Apply,[switch]$RotateAdmin,
[switch]$DisableSmb1,[switch]$DisableDcSpooler,[switch]$UpdateSignatures,
[switch]$BackupServices,[switch]$BackupWebContent,[string]$SystemStateTarget,[switch]$Hunt)
[pscustomobject]@{Host=$ExpectedHost;Apply=$Apply.IsPresent;Rotate=$RotateAdmin.IsPresent;
Smb1=$DisableSmb1.IsPresent;Spooler=$DisableDcSpooler.IsPresent;
Hunt=$Hunt.IsPresent;Backup=$BackupServices.IsPresent} |
ConvertTo-Json -Compress
'''
        for host in ('CAI-DC01', 'CAI-WEB01'):
            with self.subTest(host=host), TemporaryDirectory(dir=ROOT / 'tests') as tmp:
                folder = Path(tmp)
                source = (ROOT / 'windows' / f'{host}.ps1').read_text()
                (folder / f'{host}.ps1').write_text(source.replace('#Requires -RunAsAdministrator', ''))
                (folder / 'Invoke-BoilerstormBaseline.ps1').write_text(fake)

                def run(*args):
                    result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                                             '-File', str(folder / f'{host}.ps1'), *args],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    return [json.loads(line) for line in result.stdout.splitlines()]

                first = run()
                self.assertEqual(len(first), 2)
                self.assertTrue(first[0]['Apply'])
                self.assertTrue(first[0]['Rotate'])
                self.assertTrue(first[0]['Smb1'])
                self.assertEqual(first[0]['Spooler'], host == 'CAI-DC01')
                self.assertFalse(first[0]['Hunt'])
                self.assertTrue(first[0]['Backup'])
                self.assertTrue(first[1]['Hunt'])
                self.assertFalse(first[1]['Backup'])
                self.assertFalse(first[1]['Apply'])
                audit, = run('-AuditOnly')
                self.assertFalse(audit['Apply'])
                self.assertFalse(audit['Rotate'])
                explicit, = run('-Hunt')
                self.assertTrue(explicit['Hunt'])
                self.assertFalse(explicit['Apply'])
                applied, = run('-Apply')
                self.assertTrue(applied['Apply'])
                self.assertTrue(applied['Backup'])
                rotated, = run('-RotateAdmin')
                self.assertTrue(rotated['Rotate'])
                self.assertTrue(rotated['Backup'])

    def test_linux_first_run_and_explicit_modes(self):
        for host in ('cai-db01', 'cai-mail01'):
            with self.subTest(host=host), TemporaryDirectory(dir=ROOT / 'tests') as tmp:
                folder = Path(tmp)
                (folder / f'{host}.sh').write_bytes((ROOT / 'linux' / f'{host}.sh').read_bytes())
                (folder / 'boilerstorm-baseline.sh').write_bytes(
                    b'#!/usr/bin/env bash\nprintf "CALL"; printf " <%s>" "$@"; printf "\\n"\n')
                wsl_path = '/mnt/' + folder.drive[0].lower() + folder.as_posix()[2:]

                def run(*args):
                    result = subprocess.run(['bash', f'{wsl_path}/{host}.sh', *args],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    return result.stdout.splitlines()

                self.assertEqual(run(), ['CALL <--rotate-admin> <--apply> <--backup-services>', 'CALL <--hunt>'])
                self.assertEqual(run('--audit-only'), ['CALL <>'])
                self.assertEqual(run('--hunt', '--backup-services'), ['CALL <--hunt> <--backup-services>'])
                self.assertEqual(run('--apply'), ['CALL <--apply> <--backup-services>'])
                self.assertEqual(run('--rotate-admin'), ['CALL <--rotate-admin> <--backup-services>'])


if __name__ == '__main__':
    unittest.main()
