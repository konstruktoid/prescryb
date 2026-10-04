#!/usr/bin/env bash
# Minimal QEMU test VMs: cloud image + cloud-init seed + user-mode networking with an SSH port forward.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="${ROOT}/.state"
USER_NAME="prescryb"
MEMORY="${VM_MEMORY:-2048}"

# name|port|image URL|checksum URL
declare -A HOSTS=(
  [almalinux10]="2201|https://repo.almalinux.org/almalinux/10/cloud/x86_64_v2/images/AlmaLinux-10-GenericCloud-latest.x86_64_v2.qcow2|https://repo.almalinux.org/almalinux/10/cloud/x86_64_v2/images/CHECKSUM"
  [trixie]="2202|https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2|https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
  [resolute]="2203|https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img|https://cloud-images.ubuntu.com/resolute/current/SHA256SUMS"
)

usage() {
  echo "usage: $0 {up|ssh|down|destroy|status} <$(printf '%s\n' "${!HOSTS[@]}" | sort | paste -sd'|')>" >&2
  exit 2
}

[[ $# -ge 2 ]] || usage
cmd="$1"
name="$2"
shift 2
[[ -v HOSTS[$name] ]] || usage
IFS='|' read -r port image_url sum_url <<<"${HOSTS[$name]}"

base="${STATE}/base/$(basename "${image_url}")"
disk="${STATE}/${name}.qcow2"
seed="${STATE}/${name}-seed.iso"
pidfile="${STATE}/${name}.pid"
key="${STATE}/id_ed25519"
known_hosts="${STATE}/known_hosts"

running() { [[ -f "${pidfile}" ]] && kill -0 "$(<"${pidfile}")" 2>/dev/null; }

ssh_base() {
  ssh -i "${key}" -p "${port}" -o IdentitiesOnly=yes \
    -o UserKnownHostsFile="${known_hosts}" -o StrictHostKeyChecking=accept-new \
    "${USER_NAME}@127.0.0.1" "$@"
}

fetch_base() {
  [[ -f "${base}" ]] && return
  mkdir -p "${STATE}/base"
  local sums file hash tmp
  file="$(basename "${image_url}")"
  sums="$(curl -fsSL "${sum_url}")"
  hash="$(grep -F "${file}" <<<"${sums}" | grep -oE '[0-9a-f]{64,128}' | head -n1)"
  [[ -n "${hash}" ]] || { echo "no checksum for ${file} in ${sum_url}" >&2; exit 1; }
  tmp="$(mktemp "${STATE}/base/dl.XXXXXX")"
  trap 'rm -f "${tmp}"' EXIT
  curl -fL -o "${tmp}" "${image_url}"
  if [[ ${#hash} -eq 128 ]]; then
    echo "${hash}  ${tmp}" | sha512sum -c -
  else
    echo "${hash}  ${tmp}" | sha256sum -c -
  fi
  mv "${tmp}" "${base}"
  trap - EXIT
}

up() {
  if running; then echo "${name} already running on port ${port}"; return; fi
  mkdir -p "${STATE}"
  [[ -f "${key}" ]] || ssh-keygen -q -t ed25519 -N '' -C prescryb-qemu -f "${key}"
  fetch_base
  [[ -f "${disk}" ]] || qemu-img create -q -f qcow2 -F qcow2 -b "${base}" "${disk}" 20G
  if [[ ! -f "${seed}" ]]; then
    local ud md
    ud="$(mktemp)"
    md="$(mktemp)"
    cat >"${ud}" <<CI
#cloud-config
hostname: ${name}
users:
  - name: ${USER_NAME}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(<"${key}.pub")
CI
    printf 'instance-id: %s\nlocal-hostname: %s\n' "${name}" "${name}" >"${md}"
    cloud-localds "${seed}" "${ud}" "${md}"
    rm -f "${ud}" "${md}"
  fi
  local accel=tcg
  [[ -w /dev/kvm ]] && accel=kvm
  qemu-system-x86_64 -machine "q35,accel=${accel}" -cpu max -smp 2 -m "${MEMORY}" \
    -drive "file=${disk},if=virtio,format=qcow2" \
    -drive "file=${seed},if=virtio,format=raw,media=cdrom,readonly=on" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${port}-:22" -device virtio-net-pci,netdev=n0 \
    -display none -serial "file:${STATE}/${name}.log" -daemonize -pidfile "${pidfile}"
  echo "${name} booting; SSH on 127.0.0.1:${port} as ${USER_NAME}, key ${key}"
  echo "wait for it with: $0 ssh ${name} true"
}

down() {
  if running; then
    local pid
    pid="$(<"${pidfile}")"
    kill "${pid}"
    while kill -0 "${pid}" 2>/dev/null; do sleep 0.2; done
  fi
  rm -f "${pidfile}"
}

case "${cmd}" in
  up) up ;;
  ssh) ssh_base "$@" ;;
  down) down ;;
  destroy)
    down
    rm -f "${disk}" "${seed}"
    # A rebuilt guest gets a new host key.
    [[ -f "${known_hosts}" ]] && ssh-keygen -q -R "[127.0.0.1]:${port}" -f "${known_hosts}" &>/dev/null
    ;;
  status) if running; then echo "${name}: running (port ${port})"; else echo "${name}: stopped"; fi ;;
  *) usage ;;
esac
