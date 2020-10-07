#!/bin/bash
# shellcheck disable=SC2005,SC2030,SC2031,SC2174
#
# This script helps manage Vault running in a multi-node cluster
# using the integrated storage (Raft) backend.
#
# Learn Guide: https://learn.hashicorp.com/vault/beta/raft-storage
#
# NOTES:
# - This script is intended only to be used in an educational capacity.
# - This script is not intended to manage a Vault in a production environment.
# - This script supports Linux and macOS
# - Linux support expects the 'ip' command instead of 'ifconfig' command

set -e

demo_home="$(pwd)"
script_name="$(basename "$0")"
os_name="$(uname -s | awk '{print tolower($0)}')"

if [ "$os_name" != "darwin" ] && [ "$os_name" != "linux" ]; then
  >&2 echo "Sorry, this script supports only Linux or macOS operating systems."
  exit 1
fi

function vault_to_network_address {
  local vault_node_name=$1

  case "$vault_node_name" in
    vault_1)
      echo "http://10.128.0.19:8200"
      ;;
    vault_2)
      echo "http://127.0.0.2:8200"
      ;;
    vault_3)
      echo "http://127.0.0.3:8200"
      ;;
    vault_4)
      echo "http://127.0.0.4:8200"
      ;;
  esac
}

# Create a helper function to address the first vault node
function vault_1 {
    (export VAULT_ADDR=http://10.128.0.19:8200 && vault "$@")
}

# Create a helper function to address the second vault node
function vault_2 {
    (export VAULT_ADDR=http://127.0.0.2:8200 && vault "$@")
}

# Create a helper function to address the third vault node
function vault_3 {
    (export VAULT_ADDR=http://127.0.0.3:8200 && vault "$@")
}

# Create a helper function to address the fourth vault node
function vault_4 {
    (export VAULT_ADDR=http://127.0.0.4:8200 && vault "$@")
}

function stop_vault {
  local vault_node_name=$1

  service_count=$(pgrep -f "$(pwd)"/config-"$vault_node_name" | wc -l | tr -d '[:space:]')

  printf "\n%s" \
    "Found $service_count Vault service(s) matching that name"

  if [ "$service_count" != "0" ] ; then
    printf "\n%s" \
      "[$vault_node_name] stopping" \
      ""

    pkill -f "$(pwd)/config-$vault_node_name"
  fi
}

function stop {
  case "$1" in
    vault_1)
      stop_vault "vault_1"
      ;;
    vault_2)
      stop_vault "vault_2"
      ;;
    vault_3)
      stop_vault "vault_3"
      ;;
    vault_4)
      stop_vault "vault_4"
      ;;
    all)
      for vault_node_name in vault_1 vault_2 vault_3 vault_4 ; do
        stop_vault $vault_node_name
      done
      ;;
    *)
      printf "\n%s" \
        "Usage: $script_name stop [all|vault_1|vault_2|vault_3|vault_4]" \
        ""
      ;;
    esac
}

function start_vault {
  local vault_node_name=$1

  local vault_network_address
  vault_network_address=$(vault_to_network_address "$vault_node_name")
  local vault_config_file=$demo_home/config-$vault_node_name.hcl
  local vault_log_file=$demo_home/$vault_node_name.log

  printf "\n%s" \
    "[$vault_node_name] starting Vault server @ $vault_network_address" \
    ""

  # vault_1 when started should not be looking for a token. It should be
  # creating the token.

  if [[ "$vault_node_name" != "vault_1" ]] ; then
    if [[ -e "$demo_home/root_token-vault_1" ]] ; then
      VAULT_TOKEN=$(cat "$demo_home"/root_token-vault_1)

      printf "\n%s" \
        "Using [vault_1] root token ($VAULT_TOKEN) to retrieve transit key for auto-unseal"
      printf "\n"
    fi
  fi

  VAULT_TOKEN=$VAULT_TOKEN VAULT_API_ADDR=$vault_network_address vault server -log-level=trace -config "$vault_config_file" > "$vault_log_file" 2>&1 &
}

function start {
  case "$1" in
    vault_1)
      start_vault "vault_1"
      ;;
    vault_2)
      start_vault "vault_2"
      ;;
    vault_3)
      start_vault "vault_3"
      ;;
    vault_4)
      start_vault "vault_4"
      ;;
    all)
      for vault_node_name in vault_1 vault_2 vault_3 vault_4 ; do
        start_vault $vault_node_name
      done
      ;;
    *)
      printf "\n%s" \
        "Usage: $script_name stop [all|vault_1|vault_2|vault_3|vault_4]" \
        ""
      ;;
    esac
}

function loopback_exists_at_address {
  case "$os_name" in
  darwin)
    echo "$(ifconfig lo0 | grep "$1" || true)" | tr -d '[:space:]'
    ;;
  linux)
    echo "$(ip addr show dev lo | grep "$1" || true)" | tr -d '[:space:]'
    echo "$(ip addr show dev lo | grep "$1" || true)" | tr -d '[:space:]'
    echo "$(ip addr show dev lo | grep "$1" || true)" | tr -d '[:space:]'
    ;;
  esac
}

function clean {

  printf "\n%s" \
    "Cleaning up the HA cluster. Removing:" \
    " - local loopback address for [vault_2], [vault_3], and [vault_4]" \
    " - configuration files" \
    " - raft storage directory" \
    " - log files" \
    " - unseal / recovery keys" \
    ""

  for loopback_address in "127.0.0.2" "127.0.0.3" "127.0.0.4" ; do
    loopback_exists=$(loopback_exists_at_address $loopback_address)
    if [[ $loopback_exists != "" ]] ; then
      printf "\n%s" \
        "Removing local loopback address: $loopback_address (sudo required)" \
        ""
        case "$os_name" in
        darwin)
          sudo ifconfig lo0 -alias $loopback_address
          ;;
        linux)
          sudo ip addr del "$loopback_address"/8 dev lo
          ;;
        esac
    fi
  done

  for config_file in $demo_home/config-vault_1.hcl $demo_home/config-vault_2.hcl $demo_home/config-vault_3.hcl $demo_home/config-vault_4.hcl ; do
    if [[ -f "$config_file" ]] ; then
      printf "\n%s" \
        "Removing configuration file $config_file"

      rm "$config_file"
      printf "\n"
    fi
  done

  for raft_storage in $demo_home/raft-vault_2 $demo_home/raft-vault_3 $demo_home/raft-vault_4 ; do
    if [[ -d "$raft_storage" ]] ; then
    printf "\n%s" \
        "Removing raft storage file $raft_storage"

      rm -rf "$raft_storage"
    fi
  done

  for key_file in $demo_home/unseal_key-vault_1 $demo_home/recovery_key-vault_2 ; do
    if [[ -f "$key_file" ]] ; then
      printf "\n%s" \
        "Removing key $key_file"

      rm "$key_file"
    fi
  done

  for token_file in $demo_home/root_token-vault_1 $demo_home/root_token-vault_2 ; do
    if [[ -f "$token_file" ]] ; then
      printf "\n%s" \
        "Removing key $token_file"

      rm "$token_file"
    fi
  done

  for vault_log in $demo_home/vault_1.log $demo_home/vault_2.log $demo_home/vault_3.log $demo_home/vault_4.log ; do
    if [[ -f "$vault_log" ]] ; then
      printf "\n%s" \
        "Removing log file $vault_log"

      rm "$vault_log"
    fi
  done


  if [[ -f "$demo_home/demo.snapshot" ]] ; then
    printf "\n%s" \
      "Removing demo.snapshot"

    rm demo.snapshot
  fi

  # to successfully demo again later, previous VAULT_TOKEN cannot be present
  unset VAULT_TOKEN

  printf "\n%s" \
    "Clean complete" \
    ""
}

function status {
  service_count=$(pgrep -f "$(pwd)"/config | wc -l | tr -d '[:space:]')

  printf "\n%s" \
    "Found $service_count Vault services" \
    ""

  if [[ "$service_count" != 4 ]] ; then
    printf "\n%s" \
    "Unable to find all Vault services" \
    ""
  fi

  printf "\n%s" \
    "[vault_1] status" \
    ""
  vault_1 status || true

  printf "\n%s" \
    "[vault_2] status" \
    ""
  vault_2 status || true

  printf "\n%s" \
    "[vault_3] status" \
    ""
  vault_3 status || true

  printf "\n%s" \
    "[vault_4] status" \
    ""
  vault_4 status || true

  sleep 2
}

function create_config {

  printf "\n%s" \
    "[vault_1] Creating configuration" \
    "  - creating $demo_home/config-vault_1.hcl"

  rm -f config-vault_1.hcl

  tee "$demo_home"/config-vault_1.hcl 1> /dev/null <<EOF
    storage "inmem" {}
    listener "tcp" {
      address = "10.128.0.19:8200"
      tls_disable = true
    }
    disable_mlock = true
EOF
  printf "\n"
}

function setup_vault_1 {
  start_vault "vault_1"
  sleep 5s

  printf "\n%s" \
    "[vault_1] initializing and capturing the unseal key and root token" \
    ""
  sleep 2s # Added for human readability

  INIT_RESPONSE=$(vault_1 operator init -format=json -key-shares 1 -key-threshold 1)

  UNSEAL_KEY=$(echo "$INIT_RESPONSE" | jq -r .unseal_keys_b64[0])
  VAULT_TOKEN=$(echo "$INIT_RESPONSE" | jq -r .root_token)

  echo "$UNSEAL_KEY" > unseal_key-vault_1
  echo "$VAULT_TOKEN" > root_token-vault_1

  printf "\n%s" \
    "[vault_1] Unseal key: $UNSEAL_KEY" \
    "[vault_1] Root token: $VAULT_TOKEN" \
    ""

  printf "\n%s" \
    "[vault_1] unsealing and logging in" \
    ""
  sleep 2s # Added for human readability

  vault_1 operator unseal "$UNSEAL_KEY"
  vault_1 login "$VAULT_TOKEN"

  printf "\n%s" \
    "[vault_1] enabling the transit secret engine and creating a key to auto-unseal vault cluster" \
    ""
  sleep 5s # Added for human readability

  vault_1 secrets enable transit
  vault_1 write -f transit/keys/unseal_key
}

function create {
  case "$1" in
    network)
      shift ;
      create_network "$@"
      ;;
    config)
      shift ;
      create_config "$@"
      ;;
    *)
      printf "\n%s" \
      "Creates resources for the cluster." \
      "Usage: $script_name create [network|config]" \
      ""
      ;;
  esac
}

function setup {
  case "$1" in
    vault_1)
      setup_vault_1
      ;;
    vault_2)
      setup_vault_2
      ;;
    vault_3)
      setup_vault_3
      ;;
    vault_4)
      setup_vault_4
      ;;
    all)
      for vault_setup_function in setup_vault_1 setup_vault_2 setup_vault_3 setup_vault_4 ; do
        $vault_setup_function
      done
      ;;
    *)
      printf "\n%s" \
      "Sets up resources for the cluster" \
      "Usage: $script_name setup [all|vault_1|vault_2|vault_3|vault_4]" \
      ""
      ;;
  esac
}

case "$1" in
  create)
    shift ;
    create "$@"
    ;;
  setup)
    shift ;
    setup "$@"
    ;;
  vault_1)
    shift ;
    vault_1 "$@"
    ;;
  vault_2)
    shift ;
    vault_2 "$@"
    ;;
  vault_3)
    shift ;
    vault_3 "$@"
    ;;
  vault_4)
    shift ;
    vault_4 "$@"
    ;;
  status)
    status
    ;;
  start)
    shift ;
    start "$@"
    ;;
  stop)
    shift ;
    stop "$@"
    ;;
  clean)
    stop all
    clean
    ;;
  *)
    printf "\n%s" \
      "This script helps manages a Vault HA cluster with raft storage." \
      "View the README.md the complete guide at https://learn.hashicorp.com/vault/beta/raft-storage" \
      "" \
      "Usage: $script_name [create|setup|status|stop|clean|vault_1|vault_2|vault_3|vault_4]" \
      ""
    ;;
esac
