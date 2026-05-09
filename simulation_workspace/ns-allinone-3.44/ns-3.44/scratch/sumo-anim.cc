#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

int main (int argc, char *argv[]) {
    // 1. Create 50 network nodes (representing our 50 SUMO vehicles)
    NodeContainer nodes;
    nodes.Create (50);

    // 2. Load the SUMO trace file and apply it to the nodes
    Ns2MobilityHelper ns2 = Ns2MobilityHelper ("mobility_trace.tcl");
    ns2.Install (); // Applies the movement to nodes matching the IDs in the trace

    // 3. Generate the XML file for NetAnim
    AnimationInterface anim ("sumo-animation.xml");

    // 4. Run the simulation for 150 seconds (matching our SUMO data)
    Simulator::Stop (Seconds (150.0));
    Simulator::Run ();
    Simulator::Destroy ();

    return 0;
}
