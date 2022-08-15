from simulation.model import Identifiers, NodeID, NodeInfo
from simulation import model as m
from typing import Union

DEFAULT_ALLOW_RULES = [
    m.FirewallRule("MySql", m.RulePermission.ALLOW)]

# Environment constants used for all instances of the chain network mysql 3306
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
        'Tomcat'
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
        'MS16_111',
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
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="C",
                                                                            port="MySql",
                                                                            credential="Mysql-Conf-file")]),
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
        services=[m.ListeningService("Weblogic_12.3.1"),
                  m.ListeningService("SSH")],
        vulnerabilities=dict(
            CVE_2017_16995=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="D",
                                                                            port="SSH",
                                                                            credential="SSHCreds")]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            ),
            CVE_2019_2729=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0,
            )
        ),
        value=70,
        properties=["Ubuntu_16.04_4.4.110", "Weblogic_12.3.1", "SSH"],
        # firewall=(),
        # agent_installed=False
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "B": m.NodeInfo(
        services=[m.ListeningService("Struts_2.3.24")],
        vulnerabilities=dict(
            CVE_2009_0097=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="I",
                                                                            port="RDP",
                                                                            credential="RDPCreds")]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=5.0
            ),
            S2_048=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=50,
        properties=["Windows_Server_2003", "Struts_2.3.24"]
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "C": m.NodeInfo(
        services=[m.ListeningService("MySql", allowedCredentials=["Mysql-Conf-file"]),
                  m.ListeningService("SSH")],
        vulnerabilities=dict(
            CVE_2017_16995=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["A", "F"]),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            ),
            MS16_111=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )
        ),
        value=100,
        properties=["Ubuntu_16.04_4.4.110", "MySql", "SSH", "Windows_10_10586"]
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "D": m.NodeInfo(
        services=[m.ListeningService("E_cology_9.0"),
                  m.ListeningService("SSH", allowedCredentials=["SSHCreds"])],
        vulnerabilities=dict(
            MS15_015=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["G"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            ),
            CNVD_2019_32204=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                # precondition=m.Precondition('True'),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=60,
        properties=["Windows_Server_2012", "E_cology_9.0", "RDP"]
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "E": m.NodeInfo(
        services=[m.ListeningService("SSH", allowedCredentials=["SSHCreds"])],
        vulnerabilities=dict(
            MS17_010=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["G"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=5.0
            ),
            MS16_111=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["H"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )
        ),
        value=200,
        properties=["Windows_7", "SSH"],
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
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=5.0
            ),
            CVE_2009_0097=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["H"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=5.0
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
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            ),
            MS16_111=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["B", "H"]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=1.0
            )),
        value=100,
        properties=["Windows_XP", "Windows_10_10586"],
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
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                cost=2.0
            ),
            CVE_2009_0097=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="E",
                                                                            port="SSH",
                                                                            credential="SSHCreds")]),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=5.0
            )
        ),
        value=500,
        properties=["Windows_7", "RDP"],
        # firewall=(),
        # agent_installed=False,
        # privilege_level=m.PrivilegeLevel.NotFound,
        # owned_string='',
    ),
    "I": m.NodeInfo(
        services=[m.ListeningService("smb"),
                  m.ListeningService("RDP", allowedCredentials=["RDPCreds"])],
        vulnerabilities=dict(
            MS09_050=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=5.0
            ),
            CVE_2022_0847=m.VulnerabilityInfo(
                description='',
                type=m.VulnerabilityType.LOCAL,
                outcome=m.AdminEscalation(),
                rates=m.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                # URL='',
                cost=1.0
            )
        ),
        value=100,
        properties=["Windows_Server_2008", "smb", "RDP"],
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
