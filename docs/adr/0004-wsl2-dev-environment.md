# ADR 0004: WSL2 (Ubuntu 24.04) as the development environment

Status: Accepted (2026-07-04)

## Context
Development happens on a Windows laptop; the product deploys as Linux
containers.

## Decision
All code, tooling, and containers run inside WSL2 Ubuntu. The repository
lives on the Linux filesystem (~/projects), never under /mnt/c.

## Consequences
+ Dev environment matches production OS family.
- IDE must be configured for WSL interpreter/terminal.
