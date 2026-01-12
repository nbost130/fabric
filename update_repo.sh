#!/bin/bash

set -e

echo "Starting repository update process..."

if ! git diff --quiet --exit-code || ! git diff --cached --quiet --exit-code; then
	echo "Stashing uncommitted changes..."
	git stash
	STASHED=true
else
	STASHED=false
	echo "No uncommitted changes to stash."
fi

echo "Pulling latest changes with rebase..."
if ! git pull --rebase; then
	echo "Pull failed. Aborting rebase if in progress..."
	git rebase --abort 2>/dev/null || true
	if [ "$STASHED" = true ]; then
		echo "Restoring stashed changes..."
		git stash pop 2>/dev/null || echo "Warning: Could not restore stashed changes. Manual intervention may be needed."
	fi
	echo "Pull failed. Exiting."
	exit 1
fi

if [ "$STASHED" = true ]; then
	echo "Restoring stashed changes..."
	if ! git stash pop; then
		echo "Warning: Stash pop failed. There may be merge conflicts. Manual resolution needed."
		exit 1
	fi
fi

echo "Staging all changes..."
git add .

if git diff --cached --quiet; then
	echo "No changes to commit."
	exit 0
fi

echo "Analyzing changes to generate commit message..."
CHANGED_FILES=$(git diff --cached --name-status)

if echo "$CHANGED_FILES" | grep -q '^A.*'; then
	MSG="feat: add new files"
elif echo "$CHANGED_FILES" | grep -q '^D.*'; then
	MSG="feat: remove files"
elif echo "$CHANGED_FILES" | grep -q '\.md$'; then
	MSG="docs: update documentation"
elif echo "$CHANGED_FILES" | grep -q '\.test\.\|\.spec\.'; then
	MSG="test: update tests"
elif echo "$CHANGED_FILES" | grep -q '\.js$\|\.ts$\|\.py$\|\.rb$\|\.go$\|\.rs$\|\.java$'; then
	if git diff --cached | grep -q "^-.*\(fix\|bug\|error\)"; then
		MSG="fix: bug fixes"
	else
		MSG="feat: code updates"
	fi
else
	MSG="chore: update files"
fi

echo "Generated commit message: $MSG"

echo "Committing changes..."
git commit -m "$MSG"

echo "Pushing to remote..."
if ! git push; then
	echo "Push failed. Please check your remote configuration or network connection."
	exit 1
fi

echo "Repository update completed successfully."
