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

import com.sun.jna.Structure;

/**
 * <code>pcap_rmtauth</code> - 
 * <p>This structure keeps the information needed to autheticate the user on a remote machine.
 * The remote machine can either grant or refuse the access according to the information
 * provided. In case the NULL authentication is required, both 'username' and 'password' can be NULL pointers.
 * This structure is meaningless if the source is not a remote interface;
 * in that case, the functions which requires such a structure can accept a NULL pointer as well.
 * 
 * @author Andrei Sochirca
 */
public class pcap_rmtauth extends Structure {
    /**
     * Type of the authentication required.
     */
    public int type;
    /**
     * Zero-terminated string containing the username that has to be used
     * on the remote machine for authentication.
     */
    public String username;
    /**
     * Zero-terminated string containing the password that has to be used
     * on the remote machine for authentication.
     */
    public String password;
    
    /**
     * Constructor.
     */
    public pcap_rmtauth() {
    }
}