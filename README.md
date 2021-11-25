# iptables-bash
Best practice iptables bash script.

This scirpt implements a stateful firewall filtering ingoing traffic. Outgoing traffic is accepted.

## How to use
- Add your TCP / UDP ports that should be allowed under the custom sections.
- Execute the script with sudo permissions.
- Validate the function of your network.
- Make the rules persistant with ``iptables-save``
