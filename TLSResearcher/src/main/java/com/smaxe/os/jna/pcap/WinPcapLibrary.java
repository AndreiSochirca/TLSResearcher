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

/**
 * <code>WinPcapLibrary</code> - win pcap library.
 * 
 * @author Andrei Sochirca
 */
public interface WinPcapLibrary extends PcapLibrary {
    /**
     * Drops an active connection (active mode only).
     * <pre>
     * This function has been defined to allow the client dealing with the 'active mode'.
     * This function closes an active connection that is still in place and it purges
     * the host name from the 'activeHost' list. From this point on,
     * the client will not have any connection with that host in place.
     * </pre>
     * 
     * @param host
     * @param errbuf
     * @return <code>0</code> if everything is fine, <code>-1</code> if some errors occurred,
     * the error message is returned into the errbuf variable
     */
    public int pcap_remoteact_close(String host, byte[] errbuf);
    
    /**
     * Clean the socket that is currently used in waiting active connections.
     * <pre>
     * This function does a very dirty job. The fact is that is the waiting socket is not freed
     * if the pcap_remoteaccept() is killed inside a new thread.
     * This function is able to clean the socket in order to allow the next calls to
     * pcap_remoteact_accept() to work.
     * This function is useful *only* if you launch pcap_remoteact_accept() inside a new thread,
     * and you stops (not very gracefully) the thread (for example because the user changed idea,
     * and it does no longer want to wait for an active connection).
     * So, basically, the flow should be the following:
     * launch a new thread
     * call the pcap_remoteact_accept
     * if this new thread is killed, call pcap_remoteact_cleanup().
     * 
     * This function has no effects in other cases.
     * </pre>
     */
    public void pcap_remoteact_cleanup();    
}