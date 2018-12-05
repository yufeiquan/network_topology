"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and router
        leftHost = self.addHost( 'h1', ip="10.0.1.100/24", defaultRoute="via 10.0.1.1" )
        rightHost = self.addHost( 'h2', ip="10.0.2.100/24", defaultRoute="via 10.0.2.1" )
        underHost = self.addHost( 'h3', ip="10.0.3.100/24", defaultRoute="via 10.0.3.1" )
        midSwitch = self.addSwitch( 's1' )

        # Add links
        self.addLink( leftHost, midSwitch )
        self.addLink( rightHost, midSwitch )
        self.addLink( underHost, midSwitch )


topos = { 'mytopo': ( lambda: MyTopo() ) }
