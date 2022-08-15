from simulation.model import Identifiers, NodeID, NodeInfo
from simulation import model as m
from typing import Union

DEFAULT_ALLOW_RULES = [
    m.FirewallRule("MySql", m.RulePermission.ALLOW)]

# Environment constants used for all instances of the chain network mysql 3306
"""     '7001',
        '22',
        '8080',
        '3389',
        '3306',
        '139',
        '5006',
        '445',"""

ENV_IDENTIFIERS = Identifiers(
    properties=[
        'Windows_7',
        'Windows_XP',
        'Windows_Server_2003',
        'Windows_Server_2008',
        'Windows_Server_2012',
        'Ubuntu_16.04_4.4.110',
        'Windows_10_10586',
        'Ubuntu_20.04_5.8.0',
        'Weblogic_12.3.1',
        'Struts_2.3.24',
        'MySql',
        'E_cology_9.0',
        'SSH',
        'RDP',
        'smb',
        'nss',
        'Tomcat',
    ],
    ports=[
        'Weblogic_12.3.1',
        'Struts_2.3.24',
        'MySql',
        'E_cology_9.0',
        'SSH',
        'RDP',
        'smb',
        'nss',
        'Tomcat'
    ],
    local_vulnerabilities=[
        'CVE_2017_16995',
        'CVE_2009_0097',
        'MS15_015',
        'MS16-111',
        'CVE_2022_0847',
        'Search'
    ],
    remote_vulnerabilities=[
        'CVE_2019_2729',
        'S2_048',
        'MS17_010',
        'MS08_067',
        'CNVD_2019_32204',
        'CVE_2019_0708',
        'MS09_050'
    ]
)

nodes = {
    "start": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            Search=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["A", "B"]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=0,
        properties=[],
        # firewall=(),
        agent_installed=True
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "A": m.NodeInfo(
        services=[],
        firewall=m.FirewallConfiguration(incoming=DEFAULT_ALLOW_RULES,
                                         outgoing=DEFAULT_ALLOW_RULES),
        vulnerabilities=dict(
            CVE_2017_16995=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="C",
                                       port="MySql",
                                       credential="Mysql-Conf-file")]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            ),
            CVE_2019_2729=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LocalUserEscalation(),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0,
            )
        ),
        value=50,
        properties=["Ubuntu_16.04_4.4.110"],
        # firewall=(),
        # agent_installed=False
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "B": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            CVE_2009_0097=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.SystemEscalation(),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            ),
            S2_048=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.AdminEscalation(),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=30,
        properties=["Windows_Server_2003"]
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "C": m.NodeInfo(
        services=[m.ListeningService("MySql", allowedCredentials=["Mysql-Conf-file"]),
                  m.ListeningService("SSH")],
        firewall=m.FirewallConfiguration(incoming=DEFAULT_ALLOW_RULES,
                                         outgoing=DEFAULT_ALLOW_RULES),
        vulnerabilities=dict(
            CVE_2017_16995=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["D", "E", "F", "G", "H"]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=60,
        properties=["Ubuntu_16.04_4.4.110", "MySql", "SSH"]
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "D": m.NodeInfo(
        services=[m.ListeningService("E_cology_9.0")],
        vulnerabilities=dict(
            MS15_015=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.SystemEscalation(),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            ),
            CNVD_2019_32204=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["C", "E", "F", "G", "H"]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=60,
        properties=["Windows_Server_2012", "E_cology_9.0"]
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "E": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            MS17_010=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["C", "D", "F", "G", "H"]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=50,
        properties=["Windows_7"],
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "F": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            MS17_010=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["C", "D", "E", "G", "H"]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=50,
        properties=["Windows_7"],
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "G": m.NodeInfo(
        services=[],
        vulnerabilities=dict(
            MS08_067=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["C", "D", "E", "F", "H"]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=50,
        properties=["Windows_XP"],
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "H": m.NodeInfo(
        services=[m.ListeningService("RDP")],
        vulnerabilities=dict(
            CVE_2019_0708=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["C", "D", "E", "F", "G", "I"]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=300,
        properties=["Windows_7", "RDP"],
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "I": m.NodeInfo(
        services=[m.ListeningService("smb")],
        vulnerabilities=dict(
            MS09_050=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.AdminEscalation(),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=1000,
        properties=["Windows_Server_2008", "smb"],
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    )
}
global_vulnerability_library = dict([])

def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )
