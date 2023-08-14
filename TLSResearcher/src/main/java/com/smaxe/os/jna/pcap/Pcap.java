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

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * <code>Pcap</code> - Pcap library utility methods/constants.
 * 
 * @author Andrei Sochirca
 */
public final class Pcap extends Object {
    /**
     * <code>MODE_CAPT</code> - 0 : Capture mode, to be used when calling pcap_setmode().
     */
    public final static int MODE_CAPT = 0;
    /**
     * <code>MODE_STAT</code> - 1 : Statistical mode, to be used when calling pcap_setmode().
     */
    public final static int MODE_STAT = 1;
    
    /**
     * <code>PCAP_IF_LOOPBACK</code> - 0x00000001 : interface is loopback.
     */
    public final static int PCAP_IF_LOOPBACK = 0x00000001;
    
    /**
     * <code>PCAP_ERRBUF_SIZE</code> - 256 : size to use when allocating
     * the buffer that contains the libpcap errors.
     */
    public final static int PCAP_ERRBUF_SIZE = 256;
    
    /**
     * <code>PCAP_OPENFLAG_PROMISCUOUS</code> - 1 : 
     * Defines if the adapter has to go in promiscuous mode.
     * It is '1' if you have to open the adapter in promiscuous mode, '0' otherwise.
     * Note that even if this parameter is false, the interface could well be in promiscuous
     * mode for some other reason (for example because another capture process
     * with promiscuous mode enabled is currently using that interface).
     * On on Linux systems with 2.2 or later kernels (that have the "any" device),
     * this flag does not work on the "any" device; if an argument of "any" is supplied,
     * the 'promisc' flag is ignored.
     */
    public final static int PCAP_OPENFLAG_PROMISCUOUS = 1;
    /**
     * <code>PCAP_OPENFLAG_DATATX_UDP</code> - 2 : 
     * Defines if the data trasfer (in case of a remote capture) has to be done with UDP protocol.
     * If it is '1' if you want a UDP data connection, '0' if you want a TCP data connection;
     * control connection is always TCP-based. A UDP connection is much lighter,
     * but it does not guarantee that all the captured packets arrive to the client workstation.
     * Moreover, it could be harmful in case of network congestion.
     * This flag is meaningless if the source is not a remote interface. In that case, it is simply ignored.
     */
    public final static int PCAP_OPENFLAG_DATATX_UDP = 2;
    /**
     * <code>PCAP_OPENFLAG_NOCAPTURE_RPCAP</code> - 4 :
     * Defines if the remote probe will capture its own generated traffic.
     * In case the remote probe uses the same interface to capture traffic and
     * to send data back to the caller, the captured traffic includes the RPCAP
     * traffic as well.
     * If this flag is turned on, the RPCAP traffic is excluded from the capture,
     * so that the trace returned back to the collector is does not include this traffic.
     */
    public final static int PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4;
    /**
     * <code>PCAP_OPENFLAG_NOCAPTURE_LOCAL</code> - 8 :
     * Defines if the local adapter will capture its own generated traffic.
     * This flag tells the underlying capture driver to drop the packets that were sent by itself.
     * This is usefult when building applications like bridges,
     * that should ignore the traffic they just sent.
     */
    public final static int PCAP_OPENFLAG_NOCAPTURE_LOCAL = 8;
    /**
     * <code>PCAP_OPENFLAG_MAX_RESPONSIVENESS</code> - 16 :
     * This flag configures the adapter for maximum responsiveness.
     * In presence of a large value for nbytes, WinPcap waits for the arrival
     * of several packets before copying the data to the user.
     * This guarantees a low number of system calls, i.e. lower processor usage,
     * i.e. better performance, which is good for applications like sniffers.
     * If the user sets the PCAP_OPENFLAG_MAX_RESPONSIVENESS flag,
     * the capture driver will copy the packets as soon as the application is
     * ready to receive them. This is suggested for real time applications
     * (like, for example, a bridge) that need the best responsiveness.
     */
    public final static int PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16;
    
    /**
     * <code>PCAP_SRC_FILE_STRING</code> - "file://" : String that will be used to determine the type of source
     * in use (file, remote/local interface).
     * This string will be prepended to the interface name in order to create a string
     * that contains all the information required to open the source.
     * This string indicates that the user wants to open a capture from a local file.
     */
    public final static String PCAP_SRC_FILE_STRING = "file://";
    
    /**
     * <code>PCAP_SRC_IF_STRING</code> - "rpcap://" : String that will be used
     * to determine the type of source in use (file, remote/local interface).
     * This string will be prepended to the interface name in order to create a string
     * that contains all the information required to open the source.
     * This string indicates that the user wants to open a capture from a network interface.
     * This string does not necessarily involve the use of the RPCAP protocol.
     * If the interface required resides on the local host, the RPCAP protocol is not
     * involved and the local functions are used.
     */
    public final static String PCAP_SRC_IF_STRING = "rpcap://";
    
    /**
     * Creates and returns error buffer.
     * 
     * @return error buffer
     */
    public static byte[] createErrorBuffer() {
        return new byte[PCAP_ERRBUF_SIZE];
    }
    
    /**
     * @param ref_pcap_if
     * @return {@link pcap_if} iterator
     */
    public static Iterable<pcap_if> iterate(ref_pcap_if ref_pcap_if) {
        return new IterableIterator<pcap_if>(new PcapIfIterator(ref_pcap_if.getValue()));
    }
    
    /**
     * <code>IterableIterator</code> - {@link Iterable} implementation that wraps
     * {@link Iterator}.
     * 
     * @param <T>
     * @author Andrei Sochirca
     */
    private final static class IterableIterator<T> extends Object implements Iterable<T> {
        // fields
        private final Iterator<T> iterator;
        
        /**
         * Constructor.
         * 
         * @param iterator iterator
         */
        public IterableIterator(final Iterator<T> iterator) {
            this.iterator = iterator;
        }
        
        // Iterable implementation
        
        public Iterator<T> iterator() {
            return iterator;
        }
    }    
    
    /**
     * <code>PcapIfIterator</code> - {@link pcap_if} iterator.
     */
    private final static class PcapIfIterator extends Object implements Iterator<pcap_if> {
        // fields
        private pcap_if pcap_if = null;
        
        /**
         * Constructor.
         * 
         * @param pcap_if
         */
        public PcapIfIterator(pcap_if pcap_if) {
            this.pcap_if = pcap_if;
        }
        
        // Iterator implementation
        
        public boolean hasNext() {
            return pcap_if != null;
        }
        
        public pcap_if next() {
            if (!hasNext()) throw new NoSuchElementException();
            
            pcap_if pcap_if = this.pcap_if;
            
            this.pcap_if = pcap_if.next();
            
            return pcap_if;
        }
        
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }
    
    /**
     * Constructor.
     */
    private Pcap() {
    }
}