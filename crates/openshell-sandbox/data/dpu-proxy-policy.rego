# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

package openshell

default allow = false

allow if {
	some dest in data.allowed_destinations
	host_matches(dest, lower(input.destination_host))
	port_matches(dest, input.destination_port)
}

host_matches(dest, host) if {
	not contains(dest.host, "*")
	lower(dest.host) == host
}

host_matches(dest, host) if {
	contains(dest.host, "*")
	glob.match(lower(dest.host), ["."], host)
}

port_matches(dest, port) if {
	dest.ports[_] == port
}
