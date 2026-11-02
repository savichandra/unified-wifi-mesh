/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <openssl/bio.h> /* BasicInput/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include "em.h"
#include "em_mgr.h"
#include "em_msg.h"
#include "em_cmd.h"
#include "util.h"
#include <dirent.h>
#include <fstream>
#include <linux/if.h>

#ifdef AL_SAP
#include "al_service_access_point.h"

extern AlServiceAccessPoint* g_sap;
#endif

void em_mgr_t::io_process(em_bus_event_type_t type, char *data, unsigned int len, em_cmd_params_t *params)
{
    em_event_t *evt;
    em_bus_event_t *bevt;

    evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    evt->type = em_event_type_bus;
    bevt = &evt->u.bevt;
    bevt->type = type;
    bevt->data_len = len;

	if (data != NULL) {
    	memcpy(bevt->u.subdoc.buff, data, len);
	}

	if (params != NULL) {
		memcpy(&bevt->params, params, sizeof(em_cmd_params_t));
	}

    push_to_queue(evt);
}

void em_mgr_t::io_process(em_bus_event_type_t type, unsigned char *data, unsigned int len, em_cmd_params_t *params)
{
    em_event_t *evt;
    em_bus_event_t *bevt;

    evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    evt->type = em_event_type_bus;
    bevt = &evt->u.bevt;
    bevt->type = type;
    bevt->data_len = len;

	if (data != NULL) {
    	memcpy(bevt->u.raw_buff, data, len);
	}

	if (params != NULL) {
		memcpy(&bevt->params, params, sizeof(em_cmd_params_t));
	}

    push_to_queue(evt);
}

bool em_mgr_t::io_process(em_event_t *evt)
{
    em_event_t *e;
    em_bus_event_t *bevt;
    bool should_wait;

    bevt = &evt->u.bevt;
    //em_cmd_t::dump_bus_event(bevt);

    e = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    memcpy(reinterpret_cast<unsigned char *>(e), reinterpret_cast<unsigned char *>(evt), sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);

    push_to_queue(e);

    // check if the server should wait
    should_wait = false;

    switch (evt->type) {
        case em_event_type_bus:
            bevt = &evt->u.bevt;
            if (bevt->type != em_bus_event_type_dm_commit) {
                should_wait = true;
            }
            break;

        default:
            break;
    }

    return should_wait;
}

void em_mgr_t::proto_process(unsigned char *data, unsigned int len, em_t *al_em)
{
    em_event_t	*evt;
    em_t *em = NULL;

    em = find_em_for_msg_type(data, len, al_em);
    if (em == NULL) {
        em_printfout("Error: find_em_for_msg_type failed");
        return;
    }

    evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t)));
    if (evt == NULL) {
        em_printfout("Error: malloc failed for em_event_t structure");
        return;
    }

    evt->type = em_event_type_frame;
    evt->u.fevt.frame = static_cast<unsigned char *>(malloc(len));
    if (evt->u.fevt.frame == NULL) {
        em_printfout("Error: malloc failed for frame buffer (requested size=%u)", len);
        free(evt);
        return;
    }

    memcpy(evt->u.fevt.frame, data, len);
    evt->u.fevt.frame_len = len;
    em->push_to_queue(evt);
}

void em_mgr_t::delete_nodes()
{
    em_t *em = NULL, *tmp;

    em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    while (em != NULL) {
        tmp = em;
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
        if (tmp->is_al_interface_em() == false) {
            delete_node(tmp->get_radio_interface());
        }

    }
}

void em_mgr_t::delete_node(em_interface_t *ruid)
{
    em_t *em = NULL;
    mac_addr_str_t	mac_str;

    dm_easy_mesh_t::macbytes_to_string(ruid->mac, mac_str);

    if ((em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str))) == NULL) {
        printf("%s:%d: Can not find node with key:%s\n", __func__, __LINE__, mac_str);
        return;
    }

    em->stop();
    em->deinit();
	pthread_mutex_lock(&m_mutex);
	hash_map_remove(m_em_map, mac_str);
	pthread_mutex_unlock(&m_mutex);
    delete em;

}

em_t *em_mgr_t::create_node(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, bool is_al_mac,em_profile_type_t profile, em_service_type_t type)
{
    em_t *em = NULL;
    char mac_str[32];

    if (ruid == NULL) {
        printf("%s:%d: Invalid ruid\n", __func__, __LINE__);
        return NULL;
    }

    if (dm_easy_mesh_t::name_from_mac_address(&ruid->mac, ruid->name) != 0) {
        printf("%s:%d: ruid name cannot be determined\n", __func__, __LINE__);
    }

    dm_easy_mesh_t::macbytes_to_string(ruid->mac, mac_str);
	if (is_al_mac) {
		strcat(mac_str, "_al");
	}
	printf("%s:%d key value used:%s\n", __func__, __LINE__, mac_str);
    em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str));

    if (em != NULL) {
        // update the em
        printf("%s:%d: node with key:%s already exists\n", __func__, __LINE__, mac_str);
        return em;
    }

    em = new em_t(ruid, band, dm, this, profile, type, is_al_mac);
    em->set_is_dpp_onboarding(is_agent_dpp_onboarding());
    if (em->init() != 0) {
        delete em;

        return NULL;
    }

    // add this em to hash map
	pthread_mutex_lock(&m_mutex);
    hash_map_put(m_em_map, strdup(mac_str), em);
	pthread_mutex_unlock(&m_mutex);
    printf("%s:%d: created entry for key:%s\n", __func__, __LINE__, mac_str);

    return em;
}

em_t *em_mgr_t::get_node_by_freq_band(em_freq_band_t *band)
{
    em_t *em = NULL;
    bool found = false;

    em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    while (em != NULL) {
        if (em->is_matching_freq_band(band) == true) {
            found = true;
            break;
        }
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
    }

    return (found == true) ? em:NULL;
}

em_t *em_mgr_t::get_al_node()
{
    em_t *em;
    bool found = false;

    em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    while (em != NULL) {
        if (em->is_al_interface_em() == true) {
            found = true;
            break;
        }
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
    }

    return (found == true) ? em:NULL;
}

em_t *em_mgr_t::get_phy_al_node()
{
    // al_node is the fake ("_al") node
    em_t* al_node = get_al_node();
    if (al_node == NULL) return NULL;
    uint8_t* al_mac = al_node->get_radio_interface_mac();

    // al_mac_str is the real MAC (no "_al" suffix)
    // al_mac_str will be the key for the real `em_t` in the `m_em_map`
    char al_mac_str[EM_MAC_STR_LEN+1] = {0};
    dm_easy_mesh_t::macbytes_to_string(al_mac, al_mac_str);
    em_t *phy_al_em = reinterpret_cast<em_t *>(hash_map_get(m_em_map, al_mac_str));
    if (phy_al_em == NULL) {
        printf("%s:%d: Can not find phy al node with key:%s\n", __func__, __LINE__, al_mac_str);
        return NULL;
    }
    return phy_al_em;
}

void em_mgr_t::get_all_em_for_al_mac(mac_address_t mac, std::vector<em_t*> &em_radios)
{
    em_t* em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    std::string mac_str = util::mac_to_string(mac);
    //em_printfout("*****al_mac:%s******", util::mac_to_string(mac).c_str());
    while (em != NULL) {
        dm_easy_mesh_t* dm = em->get_data_model();
        unsigned char* al_mac = dm->get_device()->get_dev_interface_mac();
        if (!(em->is_al_interface_em()) && (memcmp(al_mac, mac, MAC_ADDR_LEN) == 0)) {
            em_radios.push_back(em);
            //em_printfout("Added em with radio_mac:%s",
            //    util::mac_to_string(em->get_radio_interface_mac()).c_str());
        }
        em = static_cast<em_t*>(hash_map_get_next(m_em_map, em));
    }
    //em_printfout("******end*******");
}


void *em_mgr_t::mgr_input_listen(void *arg)
{
    size_t stack_size2;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_getstacksize(&attr, &stack_size2);
    pthread_attr_destroy(&attr);
    printf("%s:%d Thread stack size = %ld bytes \n", __func__, __LINE__, stack_size2);
    em_mgr_t *mgr = static_cast<em_mgr_t *>(arg);

    mgr->input_listener();
    return NULL;
}

int em_mgr_t::input_listen()
{
    size_t stack_size = 0x800000; /* 8MB */
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;
    int ret = 0;
    attrp = &attr;
    pthread_attr_init(&attr);
    // Setting explicitly stacksize as in few platforms(e.g. openwrt) if not called, the
    // new thread will inherit the default stack size which is significantly less
    // leading to stack overflow.
    ret = pthread_attr_setstacksize(&attr, stack_size);
    if (ret != 0) {
        printf("%s:%d pthread_attr_setstacksize failed for size:%ld ret:%d\n",
                __func__, __LINE__, stack_size, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&m_tid, attrp, em_mgr_t::mgr_input_listen, this) != 0) {
        printf("%s:%d: Failed to start em mgr thread\n", __func__, __LINE__);
        if(attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
        return -1;
    }

    if(attrp != NULL) {
        pthread_attr_destroy(attrp);
    }
    return 0;
}

int em_mgr_t::reset_listeners()
{
    int highest_fd = -1;
    em_t *em = NULL;

    FD_ZERO(&m_rset);

    pthread_mutex_lock(&m_mutex);
    em = static_cast<em_t *>(hash_map_get_first(m_em_map));

    while (em != NULL) {
        if (em->is_al_interface_em() == true) {
            int fd = em->get_fd();
	    if(fd >=0 && fd < FD_SETSIZE) {
                FD_SET(em->get_fd(), &m_rset);
		if(fd > highest_fd)
		    highest_fd = fd;
		else
		    em_printfout("Invalid 1905 fd=%d, skipping", fd);
            }
	}
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
    }

    pthread_mutex_unlock(&m_mutex);

    if ((m_netlink_socket >= 0) && (m_netlink_socket < FD_SETSIZE)) {
        FD_SET(m_netlink_socket, &m_rset);
	if(m_netlink_socket > highest_fd)
	   highest_fd = m_netlink_socket;
    }
    return highest_fd;
}

void em_mgr_t::nodes_listener()
{
    em_t *em = NULL;
    int rc = -1, highest_fd = -1;
    bool netlink_enabled = enable_netlink_monitoring();

    // get the current backhaul interface even if no netlink event arrives after agent startup.
    if (netlink_enabled)
        evaluate_stp_root_port();

    while (true)
    {
        // rebuild descriptor set before every select() loop including netlink socket when enabled
        highest_fd = reset_listeners();

        struct timeval tm = {};
        tm.tv_sec = static_cast<time_t>(m_timeout / 1000U);
        tm.tv_usec = static_cast<suseconds_t>((m_timeout % 1000U) * 1000U);

        rc = select(highest_fd + 1, &m_rset, NULL, NULL, &tm);

	if(rc == 0)
            continue;

	if (rc < 0) {
            if (errno == EINTR)
                continue;

            em_printfout("select() failed: %s", strerror(errno));
            break;
        }

        if(rc > 0) {
        
            bool netlink_ready = netlink_enabled && (m_netlink_socket >= 0) && 
                                 (m_netlink_socket < FD_SETSIZE) && FD_ISSET(m_netlink_socket, &m_rset);

            // process ieee1905 packets first
            em = static_cast<em_t *>(hash_map_get_first(m_em_map));

            while (em != NULL) 
            {
                if (em->is_al_interface_em() == true) {
                    int fd = -1;
		    bool ieee1905_ready = false;

                    pthread_mutex_lock(&m_mutex);
                    fd = em->get_fd();
		    ieee1905_ready = (fd >= 0 && fd < FD_SETSIZE) && FD_ISSET(fd, &m_rset);
                    pthread_mutex_unlock(&m_mutex);

                    if(ieee1905_ready) {
#ifdef AL_SAP
                        try {
                            AlServiceDataUnit sdu = g_sap->serviceAccessPointDataIndication();
                            std::vector<unsigned char> payload = sdu.getPayload();
                            // Original implementation expects whole ethernet frame
                            // not just CMDU, so we have to reconstruct it
                            std::vector<unsigned char> reconstructed_eth_frame;
                            auto first_mac = sdu.getSourceAlMacAddress();
                            reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),first_mac.begin(),first_mac.end());
                            auto second_mac = sdu.getDestinationAlMacAddress();
                            reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),second_mac.begin(),second_mac.end());

                            reconstructed_eth_frame.push_back(0x89);
                            reconstructed_eth_frame.push_back(0x3A);

                            reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),payload.begin(),payload.end());

#ifdef DEBUG_MODE   
                            em_printfout("First MAC Address: " MACSTRFMT, MAC2STR(first_mac));
                            em_printfout("Second MAC Address: " MACSTRFMT, MAC2STR(second_mac));
                            em_printfout("RECONSTRUCTED_ETH_FRAME: \t");
                            util::print_hex_dump(reconstructed_eth_frame);
#endif
                            proto_process(reconstructed_eth_frame.data(), static_cast<unsigned int>(reconstructed_eth_frame.size()), em);

                        } catch (const AlServiceException &e) {
                            if (e.getPrimitiveError() == PrimitiveError::InvalidMessage)
                                em_printfout("%s. Dropping packet", e.what());
                            else {
                                em_printfout("%s", e.what());
                                throw;
                            }
                        }
#else
                        unsigned char buff[MAX_EM_BUFF_SZ * EM_MAX_BANDS];
                        ssize_t len = read(fd, buff, sizeof(buff));
                        if (len > 0)
                            proto_process(buff, static_cast<unsigned int>(len), em);
                        else if (len < 0) {
                            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                                em_printfout("IEEE1905 read failed fd=%d: %s", fd, strerror(errno));
                        }
#endif // AL_SAP
                    }
                }
                em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
	    }
	
            if(netlink_ready)
                process_netlink_events();

        }
    }
}

void *em_mgr_t::mgr_nodes_listen(void *arg)
{
    size_t stack_size2;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_getstacksize(&attr, &stack_size2);
    printf("%s:%d Thread stack size = %ld bytes \n", __func__, __LINE__, stack_size2);
    pthread_attr_destroy(&attr);
    em_mgr_t *mgr = static_cast<em_mgr_t *>(arg);
    mgr->nodes_listener();
    return NULL;
}

int em_mgr_t::nodes_listen()
{
    size_t stack_size = 0x800000; /* 8MB */
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;
    int ret = 0;
    attrp = &attr;
    pthread_attr_init(&attr);
    // Setting explicitly stacksize as in few platforms(e.g. openwrt) if not called, the
    // new thread will inherit the default stack size which is significantly less
    // leading to stack overflow.
    ret = pthread_attr_setstacksize(&attr, stack_size);
    if (ret != 0) {
        printf("%s:%d pthread_attr_setstacksize failed for size:%ld ret:%d\n",
                __func__, __LINE__, stack_size, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&m_tid, attrp, em_mgr_t::mgr_nodes_listen, this) != 0) {
        printf("%s:%d: Failed to start em mgr thread\n", __func__, __LINE__);
        if(attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
        return -1;
    }
    if(attrp != NULL) {
        pthread_attr_destroy(attrp);
    }
    return 0;
}

void em_mgr_t::handle_timeout()
{
	m_tick_demultiplex++;

	handle_250ms_tick();

	if ((m_tick_demultiplex % EM_1_TOUT_MULT) == 0) {
		handle_1s_tick();
	}

	if ((m_tick_demultiplex % EM_2_TOUT_MULT) == 0) {
		handle_2s_tick();
	}

	if ((m_tick_demultiplex % EM_5_TOUT_MULT) == 0) {
		handle_5s_tick();
		m_tick_demultiplex = 0;
	}

}

unsigned short em_mgr_t::get_next_msg_id()
{
    m_msg_id++;
    if (m_msg_id == 0) {
        m_msg_id = 1;
    }
    return m_msg_id;
}

int em_mgr_t::start()
{
    int rc;
    em_event_t *evt;;
    struct timespec time_to_wait;
	bool started = false;
    input_listen();
    nodes_listen();
    pthread_mutex_lock(&m_queue.lock);
    while (m_exit == false) {
        rc = 0;

        /* m_queue.cond is CLOCK_MONOTONIC (util::monotonic_cond_init) */
        util::monotonic_now(&time_to_wait);
		util::add_milliseconds(&time_to_wait, m_queue.timeout);

        if (queue_count(m_queue.queue) == 0) {
            rc = pthread_cond_timedwait(&m_queue.cond, &m_queue.lock, &time_to_wait);
        }
        if ((rc == 0) || (queue_count(m_queue.queue) != 0)) {
            // dequeue data
            while (queue_count(m_queue.queue)) {
                evt = static_cast<em_event_t *>(queue_pop(m_queue.queue));
                if (evt == NULL) {
                    continue;
                }
                pthread_mutex_unlock(&m_queue.lock);
                if (((evt->type == em_event_type_bus) && ((evt->u.bevt.type == em_bus_event_type_reset) ||
                      (evt->u.bevt.type == em_bus_event_type_get_reset))) ||
						(is_data_model_initialized() == true)) {

                    handle_event(evt);
                } else if (evt->type == em_event_type_nb) {
                    handle_event(evt);
                }
                free(evt);
                pthread_mutex_lock(&m_queue.lock);
            }
        } else if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&m_queue.lock);
            //printf("%s:%d: Timeout secs: %d\n", __func__, __LINE__, time_to_wait.tv_sec);
            if (is_data_model_initialized() == true) {
				if (started == false) {
					start_complete();
					started = true;
				}
                handle_timeout();
            }
            pthread_mutex_lock(&m_queue.lock);
        } else {
            printf("%s:%d em exited with rc - %d\n",__func__,__LINE__, rc);
            pthread_mutex_unlock(&m_queue.lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&m_queue.lock);
    return 0;
}

void em_mgr_t::push_to_queue(em_event_t *evt)
{
    pthread_mutex_lock(&m_queue.lock);
    queue_push(m_queue.queue, evt);
    pthread_cond_signal(&m_queue.cond);
    pthread_mutex_unlock(&m_queue.lock);
}

em_event_t *em_mgr_t::pop_from_queue()
{
    return static_cast<em_event_t *>(queue_pop(m_queue.queue));
}

int em_mgr_t::init(const char *data_model_path)
{
    SSL_load_error_strings();
    SSL_library_init();

    m_em_map = hash_map_create();

    // initialize the egress queue
    m_queue.queue = queue_create();
    pthread_mutex_init(&m_queue.lock, NULL);
    int rc = util::monotonic_cond_init(&m_queue.cond);
    if (rc != 0) {
        em_printfout("Failed to initialize egress queue condition variable, err:%d", rc);
        pthread_mutex_destroy(&m_queue.lock);
        queue_destroy(m_queue.queue);
        hash_map_destroy(m_em_map);
        return -1;
    }

    m_queue.timeout = EM_MGR_TOUT;
    m_msg_id = 0;

    if(enable_netlink_monitoring()) {
        if (!load_stp_bridge_config()) {
            em_printfout("EasyMesh Bridge configuration failed. STP monitoring unavailable");
            return -1;
	}
        if (m_netlink_socket < 0 && create_netlink_socket() != 0) {
            em_printfout("Netlink socket creation failed");
           return -1;
        }
    }

    orch_init();

    rc = data_model_init(data_model_path);
    if (rc != 0) {
        em_printfout("Datamodel initialization failed");
        close_netlink_socket();
        return rc;
    }

    return 0;
}

em_mgr_t::em_mgr_t()
{
    m_exit = false;
    m_timeout = EM_MGR_TOUT;
    m_tick_demultiplex = 0;
    m_netlink_socket = -1;
    m_stp_root_tracker = em_stp_root_tracker_t{};
}

em_mgr_t::~em_mgr_t()
{
    close_netlink_socket();
}

int em_mgr_t::create_netlink_socket()
{
    if (m_netlink_socket >= 0) {
        em_printfout("Netlink socket creation skipped, fd=%d", m_netlink_socket);
        return 0;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        em_printfout("Failed to create netlink socket: %s", strerror(errno));
        return -1;
    }

    if (fd >= FD_SETSIZE) {
        em_printfout("Netlink fd %d exceeds FD_SETSIZE (%d)", fd, FD_SETSIZE);
        close(fd);
        return -1;
    }

    // increase kernel receive queue capacity to reduce notification loss during bursts.
    int receive_buffer = 256 * 1024;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)) < 0)
        em_printfout("Netlink receive buffer setup failed, using default buffer: %s", strerror(errno));

    struct sockaddr_nl addr = {};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;
    addr.nl_pid = 0;
    
    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        em_printfout("Netlink bind failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    m_netlink_socket = fd;
    em_printfout("Netlink RTMGRP_LINK monitorting enabled (fd=%d)", fd);

    return 0;
}

void em_mgr_t::close_netlink_socket()
{
    if (m_netlink_socket >= 0) {
        close(m_netlink_socket);
        m_netlink_socket = -1;
    }
}

void em_mgr_t::process_netlink_events()
{
    if (m_netlink_socket < 0)
        return;

    alignas(struct nlmsghdr) char buffer[EM_NETLINK_RECV_BUFFER];
    bool relevant_event = false, force_resync = false;

    // process a bounded number of datagrams so that Netlink traffic cannot monopolize the ieee1905 listener thread.
    for (int iloop = 0; iloop < EM_NETLINK_MAX_BATCH; ++iloop) {
        struct sockaddr_nl sender = {};
        struct iovec iov = {};
        iov.iov_base = buffer;
        iov.iov_len = sizeof(buffer);

        struct msghdr msg = {};
        msg.msg_name = &sender;
        msg.msg_namelen = sizeof(sender);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t len = recvmsg(m_netlink_socket, &msg, MSG_DONTWAIT);

        if (len < 0) {
            if (errno == EINTR)
                continue;

            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (errno == ENOBUFS) {
                // refresh from sysfs, as notifications may have been lost.
                force_resync = true;
                break;
            }
            em_printfout("Netlink recvmsg() failed: %s", strerror(errno));
            force_resync = true;
            break;
        }

        if (len == 0) {
            force_resync = true;
            break;
        }

         // reject truncated datagrams. A truncated event may hide a link transition.
        if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
            force_resync = true;
            continue;
        }

        if (msg.msg_namelen < sizeof(struct sockaddr_nl) || sender.nl_family != AF_NETLINK || sender.nl_pid != 0)
            continue;

        int remaining = static_cast<int>(len);
        struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buffer);
        bool malformed = false;

        while (NLMSG_OK(nlh, remaining)) {
            switch (nlh->nlmsg_type) {
	       case RTM_NEWLINK:
               case RTM_DELLINK: {
                   if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
                       malformed = true;
                       break;
                   }
                   relevant_event = true;
                   break;
                }
                case NLMSG_ERROR:
                {
                    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                        malformed = true;
                    } else {
                        struct nlmsgerr *err = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                        if (err->error != 0)
                            force_resync = true;
                    }
                    break;
                }

                case NLMSG_OVERRUN:
                    force_resync = true;
                    break;

                case NLMSG_DONE:
                    break;

                default:
                    break;
            }

            if (malformed)
                break;

            nlh = NLMSG_NEXT(nlh, remaining);
        }

        if (malformed || remaining != 0)
            force_resync = true;
    }

    if (relevant_event || force_resync)
        evaluate_stp_root_port();
}

bool em_mgr_t::load_stp_bridge_config()
{
    const char *bridge_name = std::getenv("EASYMESH_STP_BRIDGE");

    if (bridge_name == nullptr || !is_valid_ifname(bridge_name)) {
        em_printfout("Invalid or missing STP bridge interface name");
        m_stp_bridge_name.clear();
        return false;
    }

    m_stp_bridge_name = bridge_name;

    em_printfout("Netlink Bridge interface configured: %s", m_stp_bridge_name.c_str());
    return true;
}


bool em_mgr_t::enable_netlink_monitoring()
{
#ifdef EXT_NETLINK_MONITOR
    return true;
#else
    return false;
#endif
}

/*
 * Resolve the selected STP root port for the configured bridge.
 *
 * Return values:
 *
 * STP_ROOT_SUCCESS:
 *     The selected root port is resolved and in FORWARDING state.
 *     All fields in info are valid.
 *
 * STP_ROOT_NOT_FORWARDING:
 *     The selected root port is resolved but not forwarding.
 *     info contains the selected interface and its current state.
 *
 * Other errors:
 *     Resolution failed. info may contain partial information
 *     and must not be treated as a validated backhaul interface.
 *
 * This function performs read-only sysfs operations.
 */
int em_mgr_t::read_stp_root_port(em_stp_root_info_t &info)
{
    info = em_stp_root_info_t{};

    // validate the configured bridge interface name before using it to construct sysfs paths
    if (!is_valid_ifname(m_stp_bridge_name)) {
        em_printfout("Invalid or missing bridge interface name");
        return INVALID_STP_BRIDGE_INTF;
    }

    const std::string bridge_path = "/sys/class/net/" + m_stp_bridge_name;

     // check whether STP is enabled on the configured bridge interface
    unsigned int uistp_enabled = 0;

    if (!read_sysfs_uint(bridge_path + "/bridge/stp_state", uistp_enabled, 10)) {
        em_printfout("Failed to read STP state for bridge=%s", m_stp_bridge_name.c_str());
        return STP_STATE_READ_FAILED;
    }

    if (uistp_enabled == 0) {
        em_printfout("STP is disabled for bridge=%s", m_stp_bridge_name.c_str());
        return STP_DISABLED_BRIDGE_INTF;
    }

     // read the STP root-port number selected by the bridge, please note the bridge root_port value is decimal.
    unsigned int root_port = 0;
    const std::string root_port_path = bridge_path + "/bridge/root_port";

    if (!read_sysfs_uint(root_port_path, root_port, 10)) {
        em_printfout("Failed to read root port for bridge=%s", m_stp_bridge_name.c_str());
        return STP_ROOT_PORT_READ_FAILED;
    }

    info.root_port = root_port;

     // root_port value of 0 means that the local bridge currently considers itself the STP root
    if (root_port == 0) {
        return STP_ROOT_IS_BRIDGE;
    }

     // enumerate bridge member interfaces and match their port_no against the selected STP root-port number
    const std::string brif_path = bridge_path + "/brif";

    DIR *dir = opendir(brif_path.c_str());

    if (dir == nullptr) {
        em_printfout("Cannot open bridge member directory=%s: %s", brif_path.c_str(), strerror(errno));
        return STP_ROOT_BRIF_OPEN_FAILED;
    }

    bool found = false, ambiguous = false;
    int dir_error = 0;

    while (true) {
        errno = 0;
        struct dirent *entry = readdir(dir);

        if (entry == nullptr) {
            dir_error = errno;
            break;
        }

        const std::string ifname(entry->d_name);

        if (!is_valid_ifname(ifname))
            continue;

        const std::string port_path = brif_path + "/" + ifname;
        unsigned int port_no = 0;

         // please note the bridge member port_no values are represented in hex value
        if (!read_sysfs_uint(port_path + "/port_no", port_no, 16))
            continue;

         // consider only the bridge-selected root port, other bridge members may also be forwarding
        if (port_no != root_port)
            continue;

         // multiple interfaces with the same port number indicate an inconsistent bridge snapshot
        if (found) {
            ambiguous = true;
            break;
        }

        info.ifname = ifname;
        found = true;
    }

     // preserve errno from readdir() before closedir()
    const int close_ret = closedir(dir);

    if (close_ret != 0)
        em_printfout("Failed to close bridge member directory=%s: %s", brif_path.c_str(), strerror(errno));

    if (dir_error != 0) {
        em_printfout("Failed to enumerate bridge members bridge=%s: %s", m_stp_bridge_name.c_str(), strerror(dir_error));
        return STP_ROOT_BRIF_READ_FAILED;
    }

    if (!found || ambiguous) {
        em_printfout("Root port cannot be uniquely resolved bridge=%s root_port=%u", m_stp_bridge_name.c_str(), root_port);
        return STP_ROOT_NOT_FOUND;
    }

     // read the STP state of the selected root interface.
    const std::string state_path = brif_path + "/" + info.ifname + "/state";

    if (!read_sysfs_uint(state_path, info.port_state, 10)) {
        em_printfout("Failed to read port state bridge=%s interface=%s", m_stp_bridge_name.c_str(), info.ifname.c_str());
        return STP_ROOT_STATE_READ_FAILED;
    }

     // resolve the interface index
    info.ifindex = if_nametoindex(info.ifname.c_str());

    if (info.ifindex == 0) {
        em_printfout("Failed to resolve ifindex interface=%s", info.ifname.c_str());
        return STP_ROOT_IFINDEX_FAILED;
    }

    // read the root_port again after enumerating bridge members to avoid changes in root-port selection during sysfs read sequence.
    unsigned int verify_root_port = 0;

    if (!read_sysfs_uint(root_port_path, verify_root_port, 10) || verify_root_port != root_port) {
        em_printfout("Root port changed during read bridge=%s old_root_port=%u new_root_port=%u",
            m_stp_bridge_name.c_str(),
            root_port,
            verify_root_port);

        return STP_ROOT_CHANGED;
    }

    // a root_port match alone does not prove that the selected port state remained stable while sysfs entries were enumerated
    unsigned int verified_port_state = 0;

    if (!read_sysfs_uint(state_path, verified_port_state, 10))
        return STP_ROOT_STATE_READ_FAILED;

    if (verified_port_state != info.port_state)
        return STP_ROOT_CHANGED;

    // the selected root interface must be forwarding before notification
    if (info.port_state != STP_FORWARDING) {
        em_printfout("Root port not forwarding yet bridge=%s root_port=%u interface=%s state=%u",
            m_stp_bridge_name.c_str(),
            info.root_port,
            info.ifname.c_str(),
            info.port_state);

        return STP_ROOT_NOT_FORWARDING;
    }

    return STP_ROOT_SUCCESS;
}

void em_mgr_t::update_stp_root_tracker(int status, const em_stp_root_info_t &root_info)
{
    em_stp_root_tracker_t &tracker = m_stp_root_tracker;
    bool root_changed = false;

    switch (status) {
        case STP_ROOT_SUCCESS:
             // return if the same root is already active, no state transition or notification is necessary.
            if (tracker.state == STP_ROOT_TRACK_FORWARDING && is_same_stp_root(tracker.current_root, root_info)) 
                return;

            // a newly validated forwarding root is available, compare against the last validated root rather
            root_changed = tracker.has_last_valid_root && !is_same_stp_root(tracker.last_valid_root, root_info);

            if (root_changed) {
                em_printfout("Root port changed bridge=%s old_interface=%s old_ifindex=%u new_interface=%s new_ifindex=%u",
                    m_stp_bridge_name.c_str(),
                    tracker.last_valid_root.ifname.c_str(),
                    tracker.last_valid_root.ifindex,
                    root_info.ifname.c_str(),
                    root_info.ifindex);
            } else if (!tracker.has_last_valid_root) {
                em_printfout("Initial forwarding root bridge=%s interface=%s ifindex=%u",
                    m_stp_bridge_name.c_str(),
                    root_info.ifname.c_str(),
                    root_info.ifindex);
            } else {
                em_printfout("Forwarding root restored bridge=%s interface=%s ifindex=%u",
                    m_stp_bridge_name.c_str(),
                    root_info.ifname.c_str(),
                    root_info.ifindex);
            }

            tracker.current_root = root_info;
            tracker.last_valid_root = root_info;
            tracker.has_last_valid_root = true;
            tracker.state = STP_ROOT_TRACK_FORWARDING;
            break;

        case STP_ROOT_NOT_FORWARDING:
             // te bridge has selected a root port, but it is still not ready.
            if (tracker.state != STP_ROOT_TRACK_CONVERGING) {
                em_printfout("Root port convergence bridge=%s interface=%s state=%u",
                    m_stp_bridge_name.c_str(),
                    root_info.ifname.c_str(),
                    root_info.port_state);
            }

            tracker.current_root = em_stp_root_info_t{};
            tracker.state = STP_ROOT_TRACK_CONVERGING;
            break;

        case STP_ROOT_IS_BRIDGE:
        case STP_DISABLED_BRIDGE_INTF:
             // no usable upstream STP root port exists.
            if (tracker.state != STP_ROOT_TRACK_UNAVAILABLE) {
                em_printfout("No upstream forwarding root bridge=%s status=%d",
                    m_stp_bridge_name.c_str(),
                    status);
            }

            tracker.current_root = em_stp_root_info_t{};
            tracker.state = STP_ROOT_TRACK_UNAVAILABLE;
            break;

        case STP_ROOT_CHANGED:
            if (tracker.state != STP_ROOT_TRACK_UNKNOWN)
                em_printfout("Root-port snapshot unstable bridge=%s; reconciliation required", m_stp_bridge_name.c_str());

            tracker.current_root = em_stp_root_info_t{};
            tracker.state = STP_ROOT_TRACK_UNKNOWN;
            break;

        default:
            if (tracker.state != STP_ROOT_TRACK_UNKNOWN)
                em_printfout("Root-port status unknown bridge=%s status=%d", m_stp_bridge_name.c_str(), status);

            tracker.current_root = em_stp_root_info_t{};
            tracker.state = STP_ROOT_TRACK_UNKNOWN;
            break;
    }
}

bool em_mgr_t::read_sysfs_uint(const std::string &path, unsigned int &uivalue, int ibase)
{
    std::ifstream file(path);

    if (!file.is_open())
        return false;

    std::string text;

    if (!std::getline(file, text))
        return false;

    errno = 0;
    char *end = nullptr;

    const unsigned long result = std::strtoul(text.c_str(), &end, ibase);

    if (errno != 0 || end == text.c_str() || result > UINT_MAX ||
        text.find_first_not_of(" \t") == std::string::npos ||
        text.find('-') != std::string::npos)
        return false;

    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r') {
        ++end;
    }

    if (*end != '\0')
        return false;

    uivalue = static_cast<unsigned int>(result);
    return true;
}

bool em_mgr_t::is_valid_ifname(const std::string &name) const
{
    if (name.empty() || name.size() >= IFNAMSIZ || name == "." || name == "..")
        return false;

    for (char c : name) {
        if (c == '/' || c == ':' || c == ' ' || c == '\t' || c == '\n')
            return false;
    }

    return true;
}

bool em_mgr_t::is_same_stp_root(const em_stp_root_info_t &lhs, const em_stp_root_info_t &rhs)
{
    return lhs.ifindex == rhs.ifindex && lhs.root_port == rhs.root_port && lhs.ifname == rhs.ifname;
}

void em_mgr_t::evaluate_stp_root_port()
{
    em_stp_root_info_t root_info = {};
    int istatus = read_stp_root_port(root_info);

    update_stp_root_tracker(istatus, root_info);

    // notify EM agent for BH interface change
    if (istatus == STP_ROOT_SUCCESS)
        notify_backhaul_interface_change(root_info);
}

bool em_mgr_t::notify_backhaul_interface_change(const em_stp_root_info_t &root_info)
{
    // notify only for a valid forwarding STP root interface.
    if (root_info.ifname.empty() || root_info.ifindex == 0 || root_info.root_port == 0 || root_info.port_state != STP_FORWARDING)
        return false;

    // avoid duplicate backhaul interface notifications
    if (m_backhaul_interface_notify_initialized) {
        const em_stp_root_info_t &prev =  m_last_notified_backhaul_interface;

        if (prev.ifname == root_info.ifname && prev.ifindex == root_info.ifindex && prev.root_port == root_info.root_port)
                return false;
    }

    em_backhaul_interface_notify_t event = {};

    if (root_info.ifname.size() >= sizeof(event.ifname) || sizeof(event) > EM_MAX_EVENT_DATA_LEN) {
        em_printfout("Invalid backhaul interface notification payload");
        return false;
    }

    // check the interface still has the expected ifindex.
    if (if_nametoindex(root_info.ifname.c_str()) != root_info.ifindex) {
        em_printfout("Backhaul interface identity changed: %s", root_info.ifname.c_str());
        return false;
    }

    // fetch the MAC address of the selected backhaul interface.
    if (!get_backhaul_interface_mac(root_info.ifname, event.mac_addr)) {
        return false;
    }

    snprintf(event.ifname, sizeof(event.ifname), "%s", root_info.ifname.c_str());
    event.ifindex = root_info.ifindex;
    event.root_port = root_info.root_port;
    event.port_state = root_info.port_state;

    em_printfout("Backhaul interface changed: old=%s new=%s ifindex=%u root_port=%u "
        "mac=%02x:%02x:%02x:%02x:%02x:%02x",
        m_backhaul_interface_notify_initialized ? m_last_notified_backhaul_interface.ifname.c_str() : "<none>",
        root_info.ifname.c_str(),
        root_info.ifindex,
        root_info.root_port,
        event.mac_addr[0], event.mac_addr[1],
        event.mac_addr[2], event.mac_addr[3],
        event.mac_addr[4], event.mac_addr[5]);

    // notify EM Agent for BH change
    io_process(em_bus_event_type_backhaul_change, reinterpret_cast<unsigned char *>(&event), static_cast<unsigned int>(sizeof(event)));

    // update last-notified state.
    m_last_notified_backhaul_interface = root_info;
    m_backhaul_interface_notify_initialized = true;

    return true;
}

bool em_mgr_t::get_backhaul_interface_mac(const std::string &ifname, uint8_t (&mac_addr)[6]) const
{
    if(!is_valid_ifname(ifname))
        return false;

    const std::string path = "/sys/class/net/" + ifname + "/address";

    std::ifstream file(path);

    if (!file.is_open()) {
        em_printfout("Failed to open MAC address for interface %s", ifname.c_str());
        return false;
    }

    std::string mac_string;

    if (!std::getline(file, mac_string)) {
        em_printfout("Failed to read MAC address for interface %s", ifname.c_str());
        return false;
    }

    unsigned int bytes[6] = {};
    char extra = '\0';

    const int parsed = sscanf(mac_string.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x%c",
        &bytes[0], &bytes[1], &bytes[2],
        &bytes[3], &bytes[4], &bytes[5],
        &extra);

    if (mac_string.size() != 17 || parsed != 6) {
        em_printfout("Invalid MAC address for interface %s: %s", ifname.c_str(), mac_string.c_str());
        return false;
    }

    for (int iloop = 0; iloop < 6; ++iloop) {
        if (bytes[iloop] > 0xff) {
            return false;
        }
        mac_addr[iloop] = static_cast<uint8_t>(bytes[iloop]);
    }

    return true;
}
