# Physical isolation procedure

The software air-gap controls provide **logical isolation only**. They do not
prove that every radio, management controller, peripheral, or firmware path is
physically unable to communicate. Use this procedure when physical isolation is
required; record the operator, asset identifier, time, and observed result in
the site's controlled maintenance record.

1. Obtain authorization and arrange a local recovery method that does not rely
   on the network being isolated.
2. Shut the system down using the approved operating procedure and disconnect
   its power source before handling cables or removable hardware.
3. Disconnect all Ethernet, fiber, modem, USB-network, Thunderbolt, and other
   external communication cables. Remove wireless antennas or radio modules
   only when the equipment vendor's service procedure permits it.
4. If the security requirement includes power isolation, remove power from
   the network equipment and radios using the vendor-approved procedure.
   Do not open power supplies or perform live electrical work.
5. Inspect the physical configuration against the approved asset-specific
   diagram. Record each disconnected port/module and any path that could not
   be inspected or disabled.
6. Keep the system powered off until the required physical boundary is
   independently checked. On restart, separately verify the software
   quarantine state and its startup gate; software verification is not a
   substitute for the physical inspection.

This document is an operational checklist, not evidence that a particular
asset is physically isolated. Asset-specific diagrams, inspection records,
firmware configuration, and independent verification remain deployment and
evaluation evidence gaps.
