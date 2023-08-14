/**
 * Copyright (c) 2009 Andrei Sochirca, All Rights Reserved
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.  
 */
package com.smaxe.os.jna.pcap;

import com.sun.jna.Callback;
import com.sun.jna.Pointer;

/**
 * <code>pcap_handler</code> - prototype of the callback function that receives the packets.
 * 
 * @author Andrei Sochirca
 */
public interface pcap_handler extends Callback {
    /**
     * When pcap_dispatch() or pcap_loop() are called by the user, the packets are passed
     * to the application by means of this callback.
     * 
     * @param user user-defined parameter that contains the state of the capture session, it corresponds to the user parameter of pcap_dispatch() and pcap_loop()
     * @param pkt_header header associated by the capture driver to the packet, it is NOT a protocol header
     * @param pkt_data points to the data of the packet, including the protocol headers
     */
    public void callback(final String user, final pcap_pkthdr pkt_header, final Pointer pkt_data);
}