# tar files to use by VMS:
#   "ExplorerII-OpenWRT21.02-Z8106_SBOM.json", 'linux_components/hybrid_combined.json"
#
import tarfile
import sys
import os

linuxcomp_file = "linux_components/hybrid_combined.json"
def app_exit(msg):
    print(msg)
    print("\npack.py <xxxxxxxxxxxxxxSBOM.json")
    print(f"  - expect {linuxcomp_file}")
    exit(1)

# Usage: python script.py archive_name.tar.gz file1.txt file2.txt ...
if len(sys.argv) < 2:
    app_exit("Usage: ")

sbom_file = sys.argv[1]
if not os.path.isfile(sbom_file): 
    app_exit(f"Failed to find file {sbom_file}!")

if not os.path.isfile(linuxcomp_file ): 
    app_exit(f"Failed to find file {linuxcomp_file }!") 

archive_name = "ExplorerII-SBOM.tar.gz"

with tarfile.open(archive_name, "w:gz") as tar:
        tar.add(sbom_file )
        tar.add(linuxcomp_file, arcname="linux_components.json")
print(f"{archive_name} - file created")


