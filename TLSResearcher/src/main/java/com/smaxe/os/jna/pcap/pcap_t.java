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

import com.sun.jna.ptr.PointerByReference;

/**
 * <code>pcap_t</code> - descriptor of an open capture instance.
 * This structure is opaque to the user, that handles its content through the functions
 * provided by the library.
 * 
 * @author Andrei Sochirca
 */
public class pcap_t extends PointerByReference {
}