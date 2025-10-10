#!/usr/bin/env bash
set -euo pipefail

# Simple runner that:
# 1) removes go.sum
# 2) runs `go mod tidy`
# 3) starts three detached GNU screen sessions

SESS1="screen_1"
SESS2="screen_2"
SESS3="screen_3"

LOG_DIR="logs"
mkdir -p "$LOG_DIR"

# Ensure `screen` exists
if ! command -v screen >/dev/null 2>&1; then
  echo "Error: 'screen' is not installed. Install it (e.g. apt install screen) and try again."
  exit 1
fi

echo "Removing go.sum (if exists) and running 'go mod tidy'..."
rm -f go.sum
if command -v go >/dev/null 2>&1; then
  go mod tidy
else
  echo "Warning: 'go' command not found. Skipping 'go mod tidy'."
fi

start_screen() {
  local name="$1"
  local cmd="$2"
  local logfile="$3"

  # If a session with the same name exists, kill it first to ensure fresh start
  if screen -list | grep -q "\.${name}\b"; then
    echo "Killing existing screen session: $name"
    screen -S "$name" -X quit || true
    sleep 0.5
  fi

  echo "Starting screen session '$name' -> $cmd"
  # Start detached (-dmS) and run the command via bash -lc so shell features work
  screen -dmS "$name" bash -lc "$cmd" >/dev/null 2>&1

  # Give it a moment to create output
  sleep 0.3
  echo "Logs: $logfile"
}

# Start the three sessions; logs will be written by tee inside each command
start_screen "$SESS1" "go run main.go 2>&1 | tee -a \"$LOG_DIR/${SESS1}.log\"" "$LOG_DIR/${SESS1}.log"
start_screen "$SESS2" "go run worker/main.go 2>&1 | tee -a \"$LOG_DIR/${SESS2}.log\"" "$LOG_DIR/${SESS2}.log"
start_screen "$SESS3" "python3 -m http.server 8080 2>&1 | tee -a \"$LOG_DIR/${SESS3}.log\"" "$LOG_DIR/${SESS3}.log"

echo "All screens started. To attach to a screen: screen -r <session_name>"
echo "Example: screen -r $SESS1"

echo "To stop a session: screen -S <session_name> -X quit"
