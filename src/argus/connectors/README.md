# connectors/

Vendor integrations (Wazuh, Cortex XDR, FortiSIEM, ...).

Each connector will implement a common interface (defined in `domain/`)
so the platform core never depends on a specific vendor SDK or API shape.
