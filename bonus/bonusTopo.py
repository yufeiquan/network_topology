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
        leftHost = self.addHost( 'h4', ip="10.0.1.2/24", defaultRoute="via 10.0.1.1" )
        underHost = self.addHost( 'h5', ip="10.0.1.3/24", defaultRoute="via 10.0.1.1" )
        rightHost = self.addHost( 'h6', ip="10.0.2.2/24", defaultRoute="via 10.0.2.1" )
        nrightHost = self.addHost( 'h7', ip="10.0.5.2/24", defaultRoute="via 10.0.5.1" )
        midSwitch1 = self.addSwitch( 's1' )
        midSwitch2 = self.addSwitch( 's2' )
        midSwitch3 = self.addSwitch( 's3' )

        # Add links
        self.addLink( leftHost, midSwitch1 )
        self.addLink( underHost, midSwitch1 )
        self.addLink( rightHost, midSwitch2 )
        self.addLink( nrightHost, midSwitch3)
        self.addLink( midSwitch1, midSwitch2)
        self.addLink( midSwitch2, midSwitch3)



topos = { 'mytopo': ( lambda: MyTopo() ) }
