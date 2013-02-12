/*
 * Copyright 2005-2008 WSO2, Inc. http://wso2.com
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
 */


#include <axiom.h>
#include <axiom_xml_reader.h>
#include <axiom_util.h>
#include <axis2_addr.h>
#include <axutil_hash.h>
#include <axis2_options.h>
#include <axis2_svc_client.h>
#include <axis2_http_transport.h>

#include <axiom_soap_envelope.h>
#include <rampart_context.h>
#include <neethi_options.h>
#include <axis2_policy_include.h>
#include <neethi_engine.h>

#include "../include/wsf_wsdl_defines.h"
#include "../include/wsf_wsdl_data_template.h"
#include "../include/wsf_wsdl_util.h"

/**
* This function is responsible of selecting client options from either user_parameters or from sig_axiom */

/* 
* user has to set in svc_client_user_options a WSF_WSDL_HK_POLICY_STRING or WSF_WSDL_HK_POLICY_HASH according to the availability of policy. 
*/

void
wsdl_util_manage_client_options(
    const axutil_env_t* env, 
    axis2_svc_client_t* svc_client,
    axutil_hash_t* svc_client_user_options, 
    axis2_options_t* client_options, 
    const axis2_char_t* operation_name,
    axiom_node_t* wsdl_axiom,
    axis2_bool_t is_version1_wsdl,
    axiom_node_t* sig_axiom, 
    axis2_char_t* service_name,
    axis2_char_t* port_name,
    axiom_node_t** operation_axiom,
    int* soap_version)
{
    axis2_char_t* endpoint_address = NULL;
    axis2_char_t* classmap = NULL;
    axis2_char_t* proxy_host = NULL;
    axis2_char_t* proxy_port = NULL;
    axis2_bool_t option_supported = AXIS2_TRUE;  /* ;-) */

    int string_malloc_length = -1;
    axis2_bool_t is_multiple_interfaces = AXIS2_FALSE; 
    axis2_bool_t multiple_ep = AXIS2_FALSE;
    axis2_endpoint_ref_t *to_epr = NULL;    
    axis2_char_t *soap_action = NULL;
    axis2_char_t *wsa_action = NULL;
    axis2_bool_t is_http_method_post = AXIS2_TRUE;
    axiom_node_t* binding_node = NULL;

    axis2_char_t *ssl_server_key_filename = NULL;
    axis2_char_t *ssl_client_key_filename = NULL;
    axis2_char_t *passphrase = NULL; 
    axutil_hash_t* wsdl_policy_hash = NULL;

    /* allocations */
    string_malloc_length = sizeof(axis2_char_t) * 256; 
    endpoint_address = (axis2_char_t *)AXIS2_MALLOC(env->allocator, string_malloc_length); 
    classmap = (axis2_char_t *)AXIS2_MALLOC(env->allocator, string_malloc_length); 
    soap_action = (axis2_char_t *)AXIS2_MALLOC(env->allocator, string_malloc_length); 
    wsa_action = (axis2_char_t *)AXIS2_MALLOC(env->allocator, string_malloc_length); 

    strcpy(soap_action, "");
    strcpy(wsa_action, "");

    if (svc_client_user_options)
    {
        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_ENDPOINT))
        {  
            strcpy(endpoint_address, (axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_ENDPOINT, AXIS2_HASH_KEY_STRING)); 
        }
        else 
        {
            strcpy(endpoint_address, "");
        }

        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_CLASSMAP))
        {
            strcpy(classmap, (axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_CLASSMAP, AXIS2_HASH_KEY_STRING)); 
        }
        else
        {
            strcpy(classmap, "");
        }
    
        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_USE_SOAP))
        {
            axis2_char_t* use_soap = (axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_USE_SOAP, AXIS2_HASH_KEY_STRING);
            if (axutil_strcmp(use_soap, WSF_WSDL_SOAP_1_2) == 0)
            {
                *soap_version = 2;
                AXIS2_LOG_DEBUG_MSG(env->log, "soap version SOAP12");
            }
            else if (axutil_strcmp(use_soap, WSF_WSDL_SOAP_1_1) == 0)
            {
                *soap_version = 1;
                AXIS2_LOG_DEBUG_MSG(env->log, "soap version SOAP11"); 
            }
            else
            {
                 /* TODO: support REST */
            }
        }
        else
        {
            /* default to soap version 1.2 */
            *soap_version = 2;
            AXIS2_LOG_DEBUG_MSG(env->log, "default to soap version 1.2");
        }
        

        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_PROXY_HOST))
        {
            proxy_host = (axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_PROXY_HOST, AXIS2_HASH_KEY_STRING);
        }

        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_PROXY_PORT))
        {
            proxy_port = (axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_PROXY_PORT, AXIS2_HASH_KEY_STRING);
        }
        
        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_CLIENT_CERT))
        {
            ssl_server_key_filename = (axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_CLIENT_CERT, AXIS2_HASH_KEY_STRING);
        }
        
        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_PASSPHRASE))
        {
            ssl_client_key_filename = (axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_PASSPHRASE, AXIS2_HASH_KEY_STRING);
        }
        
        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_SERVER_CERT))
        {
            passphrase = (axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_SERVER_CERT, AXIS2_HASH_KEY_STRING);
        }

        if (axutil_hash_contains_key(svc_client_user_options, env, WSF_WSDL_HTTP_METHOD))
        {
            if (axutil_strcasecmp((axis2_char_t*)axutil_hash_get(svc_client_user_options, WSF_WSDL_HTTP_METHOD, AXIS2_HASH_KEY_STRING), AXIS2_HTTP_GET) == 0)
            {
                is_http_method_post = AXIS2_FALSE;   
            }     
        }

    }
    else
    {
        strcpy(endpoint_address, "");
    }
    
    is_multiple_interfaces = AXIS2_FALSE;
    
    // Load WSDL as DOM
     /* changing code for processing mutiple port types in wsdl 1.1 */
    
    /*is_multiple_interfaces = wsf_is_mutiple_port_types($wsdl_dom);*/

    /*if ($is_multiple_interfaces == FALSE){
        $wsdl_dom = wsf_get_wsdl_dom($wsdl_dom, $xslt_location);
        
        if(!$wsdl_dom)
            return "error creating WSDL Dom Document";
        
        $sig_model_dom = wsf_get_sig_model_dom($wsdl_dom, $xslt_location);
//        $schema_node = wsf_get_schema_node($wsdl_dom); 
        
    }
    else {
        $wsdl_dom = wsf_get_wsdl_dom($wsdl_dom, $xslt_location);
        $schema_node = wsf_get_schema_node($wsdl_11_dom, $wsdl_dom); 

        $sig_model_dom = wsf_process_multiple_interfaces($wsdl_dom, $sig_model_dom, $xslt_location);
    }*/
    
    if (axutil_strcmp(endpoint_address, "") == 0)
    {
        axis2_char_t* sig_endpoint_address = NULL;
        if (wsdl_util_get_endpoint_address(sig_axiom, env, &sig_endpoint_address) == AXIS2_SUCCESS)
        {
            strcpy(endpoint_address, (char *)sig_endpoint_address);
        }
    }
    else
    {
        multiple_ep = 1;
        /*multiple_ep = wsf_is_multiple_endpoints(sig_model_axiom);
        if (!multiple_ep)
            endpoint_address = wsf_get_endpoint_address(sig_model_axiom);*/
    }
    
    if (option_supported) /* get binding details */
    {
        axiom_node_t* op_axiom = NULL;
        int soap_ver = 2;
        axis2_char_t* wsa_action_binding_details = NULL;
        axis2_char_t* soap_action_binding_details = NULL;
    
        if (wsdl_util_find_operation(env,
                                     operation_name, endpoint_address,
                                     AXIS2_TRUE /* is_multiple */,
                                     sig_axiom,
                                     &op_axiom,
                                     &soap_ver) == AXIS2_SUCCESS)
        {
            *operation_axiom = op_axiom;
            *soap_version = soap_ver;
            if (wsdl_util_get_binding_details(env, 
                                              op_axiom,
                                              &wsa_action, &soap_action) == AXIS2_SUCCESS)
            {
                if (wsa_action_binding_details)
                    strcpy (wsa_action, wsa_action_binding_details);
                if (soap_action_binding_details)
                    strcpy (soap_action, soap_action_binding_details);

                /*TODO: check this condition */
                //if (wsa_action_binding_details || soap_action_binding_details) 
                //{
                //    soap_version = soap_version_binding_details; 
                //}
            }
        }
    }

    if (wsf_wsdl_util_get_binding_node(env,
                                       wsdl_axiom,
                                       is_version1_wsdl,
                                       service_name,
                                       port_name,
                                       &binding_node))
    {

        if (wsf_wsdl_util_get_all_policies_from_wsdl(env, 
                                                     wsdl_axiom,
                                                     is_version1_wsdl,
                                                     binding_node,
                                                     operation_name,
                                                     &wsdl_policy_hash))
        {
    
            wsf_wsdl_util_configure_security_for_svc_client(env,
                                                            svc_client_user_options,
                                                            wsdl_policy_hash,
                                                            svc_client);
        }
    }
                                                
    to_epr = axis2_endpoint_ref_create (env, endpoint_address);
    axis2_options_set_to (client_options, env, to_epr);
    
    /** enable ssl **/
    if (option_supported) /* wsf_client_enable_ssl */
    {
        axutil_property_t *ssl_server_key_prop = NULL;
        axutil_property_t *ssl_client_key_prop = NULL;
        axutil_property_t *passphrase_prop = NULL;

        ssl_server_key_prop =
            axutil_property_create_with_args (env, 0, AXIS2_TRUE, 0,
            axutil_strdup (env, ssl_server_key_filename));

        axis2_options_set_property (client_options, env, WSF_WSDL_SERVER_CERT, ssl_server_key_prop);

        ssl_client_key_prop = axutil_property_create_with_args (env, 0, AXIS2_TRUE, 0,
        axutil_strdup (env, ssl_client_key_filename));
        axis2_options_set_property (client_options, env, WSF_WSDL_KEY_FILE, ssl_client_key_prop);

        passphrase_prop = axutil_property_create_with_args (env, 0, AXIS2_TRUE, 0, axutil_strdup (env, passphrase));
        axis2_options_set_property (client_options, env, WSF_WSDL_SSL_PASSPHRASE, passphrase_prop);

        AXIS2_LOG_DEBUG (env->log, AXIS2_LOG_SI,
                        "[wsf-client] setting ssh options %s -- %s -- %s ",
                        ssl_server_key_filename, ssl_client_key_filename, passphrase);
    }

    if (axutil_strcmp(soap_action, "") != 0){
        axutil_string_t *action_string = axutil_string_create (env, soap_action);
        axis2_options_set_soap_action (client_options, env, action_string);
        AXIS2_LOG_DEBUG (env->log, AXIS2_LOG_SI,
                         "soap action present :- %s",
                         soap_action);
    }
    
    if (axutil_strcmp(wsa_action, "") != 0){
        axis2_options_set_action(client_options, env, wsa_action);
        AXIS2_LOG_DEBUG (env->log, AXIS2_LOG_SI,
                         "addressing action present :- %s",
                         wsa_action);
        axis2_svc_client_engage_module (svc_client, env, WSF_WSDL_MODULE_ADDRESSING);
    }
    
    if (*soap_version)
    {
      axis2_options_set_soap_version (client_options, env,
                      *soap_version);
      AXIS2_LOG_DEBUG (env->log, AXIS2_LOG_SI,
               "[wsf_wsdl]soap version in wsdl mode is %d",
               *soap_version);
    }

    /* 
    Add proxy options */
    if (proxy_host && proxy_port) 
    {
        axis2_svc_client_set_proxy (svc_client, env, proxy_host, proxy_port);
        AXIS2_LOG_DEBUG (env->log, AXIS2_LOG_SI,
                         "[wsf_wsdl_client] setting proxy options %s -- %s -- ", proxy_host, 
                         proxy_port);
    }

    /* 
    Default header type is POST, so only setting the HTTP_METHOD if GET */
    if (is_http_method_post == AXIS2_FALSE)
    {
        axutil_property_t *property = axutil_property_create (env);
        axutil_property_set_value (property, env, axutil_strdup (env, AXIS2_HTTP_GET));

        axis2_options_set_property (client_options, env, AXIS2_HTTP_METHOD, property);

        AXIS2_LOG_DEBUG_MSG(env->log, "[wsf_client] setting http method get property");
    }
}


/** 
* creates the request envelope for the payload provided */

axis2_char_t* 
wsdl_util_create_request_envelope(
    const axutil_env_t *env,
    axiom_node_t *payload,
    int soap_version)
{
    axiom_soap_envelope_t* envelope = NULL;
    axiom_soap_header_t* header = NULL;
    axiom_soap_body_t* body = NULL;
    axiom_node_t* envelope_node = NULL;

    if ((soap_version == AXIOM_SOAP11) || (soap_version == AXIOM_SOAP12))
    {
        envelope = axiom_soap_envelope_create_with_soap_version_prefix(env, soap_version, AXIOM_SOAP_DEFAULT_NAMESPACE_PREFIX);
    } 
    else 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "Unknown SOAP version");
    }

    header = axiom_soap_header_create_with_parent(env, envelope);
    if (!header)
    {
        return NULL;
    }

    body = axiom_soap_body_create_with_parent(env, envelope);
    if (!body)
    {
        return NULL;
    }
    
    if (payload)
    {
        axiom_soap_body_add_child(body, env, payload);
    }

    envelope_node = axiom_soap_envelope_get_base_node(envelope, env);
    
    return axiom_node_to_string(envelope_node, env);	 
}


/**
* creates the soap envelope from the xml buffer */

axiom_soap_envelope_t *
wsdl_util_create_soap_envelope_from_buffer(
    const axutil_env_t * env, 
    axis2_char_t* buffer,
    axis2_char_t * soap_version_uri)
{
    axiom_soap_envelope_t *soap_envelope = NULL;
    axiom_soap_builder_t *soap_builder = NULL;
    axiom_xml_reader_t *reader = NULL;
    axiom_stax_builder_t *builder = NULL;
    
    reader = axiom_xml_reader_create_for_memory(env, buffer, axutil_strlen(buffer), 
                                                WSF_WSDL_ENCODING_UTF_8, AXIS2_XML_PARSER_TYPE_BUFFER);

    builder = axiom_stax_builder_create(env, reader);

    soap_builder = axiom_soap_builder_create(env, builder, soap_version_uri);

    soap_envelope = axiom_soap_builder_get_soap_envelope(soap_builder, env);

    return soap_envelope;
}


/**
* send and recieve using the sevice client. payload is provided through the buffer. */

axiom_soap_envelope_t *
wsdl_util_send_receive_soap_envelope_with_op_client(
    const axutil_env_t* env,
    axis2_svc_client_t* svc_client,
    axis2_options_t* options,
    axis2_char_t* buffer)
{
    axiom_soap_envelope_t *res_envelope = NULL, *req_envelope = NULL;
    axis2_svc_ctx_t *svc_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_msg_ctx_t *req_msg_ctx = NULL, *res_msg_ctx = NULL;
    axutil_qname_t *op_qname = NULL;
    axis2_op_client_t *op_client = NULL;
    axis2_char_t *soap_version_uri = NULL;

    svc_ctx = axis2_svc_client_get_svc_ctx (svc_client, env);

    conf_ctx = axis2_svc_ctx_get_conf_ctx (svc_ctx, env);

    req_msg_ctx = axis2_msg_ctx_create (env, conf_ctx, NULL, NULL);

    op_qname = axutil_qname_create (env, AXIS2_ANON_OUT_IN_OP, NULL, NULL);

    op_client = axis2_svc_client_create_op_client (svc_client, env, op_qname);

    soap_version_uri = (axis2_char_t *) axis2_options_get_soap_version_uri (options, env);

    req_envelope = wsdl_util_create_soap_envelope_from_buffer (env, buffer, soap_version_uri);
    
    axis2_msg_ctx_set_soap_envelope (req_msg_ctx, env, req_envelope);
    
    axis2_op_client_add_msg_ctx (op_client, env, req_msg_ctx);
    
    axis2_op_client_execute (op_client, env, AXIS2_TRUE);
    
    res_msg_ctx =
       (axis2_msg_ctx_t *)axis2_op_client_get_msg_ctx (op_client, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
    
    if (res_msg_ctx) 
    {        
        res_envelope = axis2_msg_ctx_get_soap_envelope (res_msg_ctx, env);
    } 
    else 
    {
        res_envelope = NULL;
    }
    
    return res_envelope;
}

/**
* Configures security in the svc_client. Policies from script_client_options override policies 
* from WSDL, if any. 
*
* @param env pointer to environment struct
* @param script_client_options pointer to a hash of client options from scripting language
         WSF_WSDL_HK_POLICY_STRING given priority over WSF_WSDL_HK_POLICY_HASH if both set.
* @param wsdl_policy_hash pointer to a hash of policy axioms from wsdl
* @param svc_client pointer to the service client struct
* @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
*/
axis2_status_t
wsf_wsdl_util_configure_security_for_svc_client(
    const axutil_env_t* env, 
    axutil_hash_t* script_client_options_hash, 
    axutil_hash_t* wsdl_policy_hash,
    axis2_svc_client_t* svc_client)
{
    axis2_char_t* policy_xml_str = NULL;
    axutil_hash_t* policy_hash = NULL;
    axutil_hash_t* security_token_hash = NULL;
    axiom_node_t* input_policy_node_axiom = NULL;
    axiom_node_t* binding_policy_node_axiom = NULL;
    neethi_policy_t* merged_neethi_policy = NULL;
    axis2_status_t success = AXIS2_FAILURE;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, svc_client, AXIS2_FAILURE);	

    if (script_client_options_hash)
    {
        policy_xml_str = (axis2_char_t*)axutil_hash_get(script_client_options_hash, 
                                                        WSF_WSDL_HK_POLICY_STRING, 
                                                        AXIS2_HASH_KEY_STRING);
        policy_hash = (axutil_hash_t*)axutil_hash_get(script_client_options_hash, 
                                                      WSF_WSDL_HK_POLICY_HASH, 
                                                      AXIS2_HASH_KEY_STRING);
        security_token_hash = (axutil_hash_t*)axutil_hash_get(script_client_options_hash, 
                                                              WSF_WSDL_HK_SECURITY_TOKEN, 
                                                              AXIS2_HASH_KEY_STRING);
    }

    if (policy_xml_str)
    {
        success = wsf_wsdl_util_policy_from_xml_string(env, 
                                                       policy_xml_str, 
                                                       &input_policy_node_axiom);
    }
    else if (policy_hash)
    {
        success = wsf_wsdl_util_policy_from_options_hash(env, 
                                                         policy_hash, 
                                                         &input_policy_node_axiom);
    }
    else if (wsdl_policy_hash)
    {
        success = wsf_wsdl_util_policy_from_wsdl_policy_hash(env, 
                                                             wsdl_policy_hash, 
                                                             &input_policy_node_axiom,
                                                             &binding_policy_node_axiom);
    }
    else 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "No policies found! so security is not added");
        return AXIS2_SUCCESS; /* this is not a failure case, simply security is ommitted */
    }

    if (success)
    {
        success = AXIS2_FAILURE;

        if (security_token_hash)
        {
            if (wsf_wsdl_util_create_merged_neethi_policy(env,
                                                          input_policy_node_axiom,
                                                          binding_policy_node_axiom,
                                                          &merged_neethi_policy))
            {
                if (wsf_wsdl_util_insert_policy_to_svc_client(env,
                                                              merged_neethi_policy,
                                                              svc_client))
                {
                    if (wsf_wsdl_util_add_security_to_svc_client_configuration(env, 
                                                                        security_token_hash, 
                                                                        svc_client))
                    {	
                        success = axis2_svc_client_engage_module (svc_client, 
                                                                  env, WSF_WSDL_MODULE_SECURITY);
                    }
                }
            }
        }
    }

    return success;
}

axis2_status_t
wsf_wsdl_util_insert_policy_to_svc_client(
    const axutil_env_t* env, 
    neethi_policy_t* merged_input_neethi_policy,
    axis2_svc_client_t* svc_client)
{
    axis2_desc_t *desc = NULL;
    axis2_policy_include_t *policy_include = NULL;
    axis2_svc_t *svc = NULL;

    svc = axis2_svc_client_get_svc (svc_client, env);
    if (!svc) 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "Service is NULL");
        return AXIS2_FAILURE;
    }
    
    desc = axis2_svc_get_base (svc, env);
    if (!desc) 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "Description is NULL");
        return AXIS2_FAILURE;
    }
    
    policy_include = axis2_desc_get_policy_include (desc, env);
    if (!policy_include) 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "Policy Include is NULL");
        return AXIS2_FAILURE;
    }
    
    return axis2_policy_include_add_policy_element (policy_include, env,
                                                    AXIS2_SERVICE_POLICY, 
                                                    merged_input_neethi_policy);
}

axis2_status_t
wsf_wsdl_util_add_security_to_svc_client_configuration(
    const axutil_env_t* env,
    axutil_hash_t* security_token_hash,
    axis2_svc_client_t* svc_client)
{
    rampart_context_t* rampart_ctx = NULL;
    axis2_svc_ctx_t *svc_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_conf_t *conf = NULL;
    axutil_param_t *security_param = NULL;

    svc_ctx = axis2_svc_client_get_svc_ctx (svc_client, env);
    conf_ctx = axis2_svc_ctx_get_conf_ctx (svc_ctx, env);
    conf = axis2_conf_ctx_get_conf (conf_ctx, env);
    
    rampart_ctx = rampart_context_create(env);

    wsf_wsdl_util_set_security_token_options_to_rampart_ctx (env, security_token_hash, rampart_ctx);
    
    security_param = axutil_param_create (env, WSF_WSDL_RAMPART_CONFIGURATION, (void *)rampart_ctx);

    return axis2_conf_add_param (conf, env, security_param);
}

axis2_status_t
wsf_wsdl_util_set_security_token_options_to_rampart_ctx(
    const axutil_env_t* env,
    axutil_hash_t* security_token_hash,
    rampart_context_t* rampart_ctx)
{
    void* st_value = NULL;

    st_value = axutil_hash_get(security_token_hash, WSF_WSDL_HK_PRIVATE_KEY, AXIS2_HASH_KEY_STRING);
     
    if (st_value)
    {
        if (rampart_context_set_prv_key (rampart_ctx, env, st_value))
        {
            AXIS2_LOG_DEBUG_MSG(env->log, "Setting pvt key to the rampart context");
        }
    
        if (rampart_context_set_prv_key_type (rampart_ctx, env, AXIS2_KEY_TYPE_PEM))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting pvt key format to the rampart context");
        }
    }

    st_value = axutil_hash_get(security_token_hash, WSF_WSDL_HK_CERTIFICATE, AXIS2_HASH_KEY_STRING);

    if (st_value)
    {
        if (rampart_context_set_certificate (rampart_ctx, env, st_value))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting pub key to the rampart context");
        }

        if (rampart_context_set_certificate_type (rampart_ctx, env, AXIS2_KEY_TYPE_PEM))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting pub key format to the rampart context");
        }
    }

    st_value = axutil_hash_get(security_token_hash, WSF_WSDL_HK_RECEIVER_CERTIFICATE, AXIS2_HASH_KEY_STRING);

    if (st_value)
    {
        if (rampart_context_set_receiver_certificate (rampart_ctx, env, st_value))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting receiver certificate to the rampart context");
        }

        if (rampart_context_set_receiver_certificate_type (rampart_ctx, env, AXIS2_KEY_TYPE_PEM))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting receiver certificate type to the rampart context");
        }
    }

    st_value = axutil_hash_get(security_token_hash, WSF_WSDL_HK_USER, AXIS2_HASH_KEY_STRING);

    if (st_value)
    {
        if (rampart_context_set_user (rampart_ctx, env, (axis2_char_t*)st_value))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting user name to the rampart context");
        }
    }

    st_value = axutil_hash_get(security_token_hash, WSF_WSDL_HK_PASSWORD, AXIS2_HASH_KEY_STRING);

    if (st_value)
    {
        if (rampart_context_set_password (rampart_ctx, env, st_value))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting password to the rampart context");
        }
    }

    st_value = axutil_hash_get(security_token_hash, WSF_WSDL_HK_PASSWORD_TYPE, AXIS2_HASH_KEY_STRING);

    if (st_value)
    {
        if (rampart_context_set_password_type (rampart_ctx, env, st_value))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting password type to the rampart context");
        }
    }

    st_value = axutil_hash_get(security_token_hash, WSF_WSDL_HK_TTL, AXIS2_HASH_KEY_STRING);

    if (st_value)
    {
        if (rampart_context_set_ttl (rampart_ctx, env, (int)st_value))
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting ttl to the rampart context");
        }
    }

    st_value = axutil_hash_get(security_token_hash, WSF_WSDL_HK_PASSWORD_CALL_BACK, AXIS2_HASH_KEY_STRING);

    if (st_value)
    {
        /** TODO: implement the following 
        if (rampart_context_set_pwcb_function (rampart_ctx, 
                                               env, 
                                               wsf_password_provider_function,
                                               st_value)
        {
            AXIS2_LOG_DEBUG_MSG (env->log, "Setting password call back to the rampart context");
        }
        */
        AXIS2_LOG_DEBUG_MSG (env->log, "Password callback is still not implemented for wsdlc");
    }

    return AXIS2_SUCCESS;
}


axis2_status_t
wsf_wsdl_util_create_merged_neethi_policy(
    const axutil_env_t* env,
    axiom_node_t* input_policy_node_axiom,
    axiom_node_t* binding_policy_node_axiom,
    neethi_policy_t** merged_input_neethi_policy)
{
    axis2_status_t status = AXIS2_SUCCESS;
    neethi_policy_t *input_neethi_policy = NULL;
    axiom_element_t *input_policy_root_ele = NULL;
    neethi_policy_t *binding_neethi_policy = NULL;
    axiom_element_t *binding_policy_root_ele = NULL;
    neethi_policy_t *normalized_input_neethi_policy = NULL;
    neethi_policy_t *normalized_binding_neethi_policy = NULL;
    
    if (binding_policy_node_axiom) 
    {
        if (axiom_node_get_node_type (binding_policy_node_axiom, env) == AXIOM_ELEMENT) 
        {
            binding_policy_root_ele = 
                (axiom_element_t*)axiom_node_get_data_element(binding_policy_node_axiom, env);
            
            if (binding_policy_root_ele) 
            {
                binding_neethi_policy = neethi_engine_get_policy (env, 
                                                                  binding_policy_node_axiom,
                                                                  binding_policy_root_ele);
                normalized_binding_neethi_policy = 
                    neethi_engine_get_normalize(env, AXIS2_FALSE, binding_neethi_policy);
                neethi_policy_free(binding_neethi_policy, env);
                binding_neethi_policy = NULL;
            }
        }
    }
    
    if (input_policy_node_axiom) 
    {
        if (axiom_node_get_node_type (input_policy_node_axiom, env) == AXIOM_ELEMENT) 
        {
            input_policy_root_ele =
                (axiom_element_t *)axiom_node_get_data_element (input_policy_node_axiom, env);

            if (input_policy_root_ele) 
            {
                input_neethi_policy =  neethi_engine_get_policy (env, 
                                                                 input_policy_node_axiom,
                                                                 input_policy_root_ele);
                normalized_input_neethi_policy = 
                    neethi_engine_get_normalize(env, AXIS2_FALSE, input_neethi_policy);
                neethi_policy_free(input_neethi_policy, env);
                input_neethi_policy = NULL;
            } 
        }
    }
    
    if (normalized_input_neethi_policy && normalized_binding_neethi_policy)
    {
        *merged_input_neethi_policy = 
            neethi_engine_merge(env, normalized_input_neethi_policy, normalized_binding_neethi_policy);
        neethi_policy_free(normalized_binding_neethi_policy, env);
        neethi_policy_free(normalized_input_neethi_policy, env);
        AXIS2_LOG_DEBUG_MSG(env->log, "Outgoing policies merged");
    }
    else if (!normalized_input_neethi_policy && normalized_binding_neethi_policy)
    {
        *merged_input_neethi_policy = normalized_binding_neethi_policy;
        neethi_policy_free(normalized_binding_neethi_policy, env);
        AXIS2_LOG_DEBUG_MSG(env->log, "Binding policy is set");
    }    
    else if (normalized_input_neethi_policy && !normalized_binding_neethi_policy)
    {
        *merged_input_neethi_policy = normalized_input_neethi_policy;
        neethi_policy_free(normalized_input_neethi_policy, env);
        AXIS2_LOG_DEBUG_MSG(env->log, "Input policy is set");
    }
    else
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "Valid policies not found");
        status = AXIS2_FAILURE;
    }
    
    return status;
}


axis2_status_t
wsf_wsdl_util_policy_from_xml_string(
    const axutil_env_t* env, 
    axis2_char_t* policy_xml_str, 
    axiom_node_t** input_policy_node_axiom)
{
    *input_policy_node_axiom = wsf_wsdl_util_deserialize_buffer(env, policy_xml_str);

    return (*input_policy_node_axiom)? AXIS2_SUCCESS: AXIS2_FAILURE;
}

axis2_char_t*
wsf_wsdl_util_get_rampart_token_value(
    axis2_char_t* token_ref)
{
    if(strcmp(token_ref, WSF_WSDL_ISSUER_SERIAL) == 0)
        return WSF_WSDL_RP_REQUIRE_ISSUER_SERIAL_REFERENCE;
    if(strcmp(token_ref, WSF_WSDL_KEYIDENTIFIER) == 0)
        return WSF_WSDL_RP_REQUIRE_KEY_IDENTIFIER_REFERENCE;
    if(strcmp(token_ref, WSF_WSDL_EMBEDDEDTOKEN) == 0)
        return WSF_WSDL_RP_REQUIRE_EMBEDDED_TOKEN_REFERENCE;
    if(strcmp(token_ref, WSF_WSDL_THUMBPRINT) == 0)
        return WSF_WSDL_RP_REQUIRE_THUMBPRINT_REFERENCE;
    else
        return NULL;
}


axis2_status_t
wsf_wsdl_util_policy_from_options_hash(
    const axutil_env_t* env, 
    axutil_hash_t* policy_hash, 
    axiom_node_t** input_policy_node_axiom)
{
    void* phash_value = NULL;
    neethi_options_t* neethi_options = NULL;
    axis2_bool_t is_server_side = AXIS2_FALSE;

    neethi_options = neethi_options_create (env);
    
    phash_value = axutil_hash_get(policy_hash, WSF_WSDL_HK_TIMESTAMP, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        if (neethi_options_set_include_timestamp (neethi_options, env, AXIS2_TRUE))
        {
            AXIS2_LOG_DEBUG_MSG(env->log, "Timestamp_enabled ");
        }
    }

    phash_value = axutil_hash_get(policy_hash, WSF_WSDL_HK_USERNAME_TOKEN, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        if (neethi_options_set_is_username_token (neethi_options, env, AXIS2_TRUE))
        {
            AXIS2_LOG_DEBUG_MSG(env->log, "username token enabled ");
        }
    }

    phash_value = axutil_hash_get(policy_hash, WSF_WSDL_HK_ENCRYPTION, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        if (neethi_options_set_encrypt_body (neethi_options, env, AXIS2_TRUE))
        {
            AXIS2_LOG_DEBUG_MSG(env->log, "encrypt enabled ");
        }
    }
    
    phash_value = axutil_hash_get(policy_hash, WSF_WSDL_HK_ALGORITHM, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        if (neethi_options_set_algorithmsuite (neethi_options, env, (axis2_char_t*)phash_value))
        {
            AXIS2_LOG_DEBUG_MSG(env->log, "algorithm suite enabled ");
        }
    }

    phash_value = axutil_hash_get(policy_hash, WSF_WSDL_HK_SIGNING, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        if (neethi_options_set_sign_body (neethi_options, env, AXIS2_TRUE))
        {
            AXIS2_LOG_DEBUG_MSG(env->log, "signing enabled ");
        }
    }

    phash_value = axutil_hash_get(policy_hash, WSF_WSDL_HK_TOKEN_REFERENCE, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        axis2_char_t* rampart_token_str = wsf_wsdl_util_get_rampart_token_value((axis2_char_t*)phash_value);
        if (neethi_options_set_keyidentifier (neethi_options, env, rampart_token_str))
        {
            AXIS2_LOG_DEBUG_MSG(env->log, "token reference enabled ");
        }

        if (is_server_side == AXIS2_TRUE)
        {
            neethi_options_set_server_side(neethi_options, env, is_server_side);
        }
    }

    phash_value = axutil_hash_get(policy_hash, WSF_WSDL_HK_ENCRYPT_SIGNATURE, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        if (neethi_options_set_signature_protection (neethi_options, env, AXIS2_TRUE))
        {
            AXIS2_LOG_DEBUG_MSG(env->log, "encrypt sign enabled ");
        }
    }

    phash_value = axutil_hash_get(policy_hash, WSF_WSDL_HK_PROTECTION_ORDER, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        if (strcmp(phash_value, WSF_WSDL_PROTECTION_ORDER_ENCRYPT_BEFORE) == 0)
        {
            if (neethi_options_set_encrypt_before_sign (neethi_options, env, AXIS2_TRUE))
            {
                AXIS2_LOG_DEBUG_MSG(env->log, "encrypt before sign enabled ");
            }
        }
        else if (strcmp(phash_value, WSF_WSDL_PROTECTION_ORDER_SIGN_BEFORE) == 0)
        {
            if (neethi_options_set_encrypt_before_sign (neethi_options, env, AXIS2_FALSE))
            {
                AXIS2_LOG_DEBUG_MSG(env->log, "sign before encrypt enabled ");
            }
        }
        else
        {
            AXIS2_LOG_ERROR_MSG(env->log, "Wrong option for protection order");
        }
    }

    if (neethi_options) 
    {
        *input_policy_node_axiom = neethi_options_get_root_node (neethi_options, env);
    }

    return (*input_policy_node_axiom)? AXIS2_SUCCESS: AXIS2_FAILURE;
}


axis2_status_t
wsf_wsdl_util_policy_from_wsdl_policy_hash(
    const axutil_env_t* env, 
    axutil_hash_t* wsdl_policy_hash, 
    axiom_node_t** input_policy_node_axiom,
    axiom_node_t** binding_policy_node_axiom)
{
    void* phash_value = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    if (!env)
    {
        return AXIS2_FAILURE;
    }

    phash_value = axutil_hash_get(wsdl_policy_hash, WSF_WSDL_OP_POLICY, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        *binding_policy_node_axiom = (axiom_node_t*)phash_value;
        status = AXIS2_SUCCESS;
    }

    phash_value = axutil_hash_get(wsdl_policy_hash, WSF_WSDL_IN_POLICY, AXIS2_HASH_KEY_STRING);
     
    if (phash_value)
    {
        *input_policy_node_axiom = (axiom_node_t*)phash_value;
        status = AXIS2_SUCCESS;
    }

    return status;
}

axiom_node_t *
wsf_wsdl_util_deserialize_buffer(
    const axutil_env_t* env,  
    axis2_char_t* buffer)
{
    axiom_node_t* payload = NULL;
    axiom_document_t* document = NULL;
    axiom_xml_reader_t* reader = NULL;
    axiom_stax_builder_t* builder = NULL;

    reader = axiom_xml_reader_create_for_memory (env, 
                                                 buffer,
                                                 axutil_strlen (buffer), 
                                                 WSF_WSDL_ENCODING_UTF_8, 
                                                 AXIS2_XML_PARSER_TYPE_BUFFER);
    if (reader) 
    {
       builder = axiom_stax_builder_create (env, reader);
    }

    if (builder) 
    {
        document = axiom_stax_builder_get_document (builder, env);
    }
     
    if (document) 
    {
        payload = axiom_document_build_all (document, env);
    }

    if (builder)
    {
        axiom_stax_builder_free_self (builder, env);
    }

    if (!payload) 
    {
        AXIS2_LOG_ERROR_MSG(env->log, "Deserialization failed..");
    }

    return payload;
}

axiom_node_t *
wsf_wsdl_util_deserialize_file(
    const axutil_env_t* env,  
    axis2_char_t* file_name)
{
    axiom_node_t* payload = NULL;
    axiom_document_t* document = NULL;
    axiom_xml_reader_t* reader = NULL;
    axiom_stax_builder_t* builder = NULL;

    reader = axiom_xml_reader_create_for_file (env, file_name, WSF_WSDL_ENCODING_UTF_8);

    if (reader) 
    {
        builder = axiom_stax_builder_create (env, reader);
    }

    if (builder) 
    {
        document = axiom_stax_builder_get_document (builder, env);
    }

    if (document) 
    {
        payload = axiom_document_build_all (document, env);
    }

    if (builder)
    {
        axiom_stax_builder_free_self (builder, env);
    }

    if (!payload) 
    {
        AXIS2_LOG_ERROR_MSG(env->log, "Deserialization failed..");
    }

    return payload;
}

axis2_status_t
wsf_wsdl_util_handle_service_security(
    const axutil_env_t* env,
    axis2_svc_t* service,
    axis2_conf_ctx_t* worker_conf_ctx,
    axutil_hash_t* script_service_user_options,
    axis2_char_t* service_name,
    axis2_char_t* port_name,
    axiom_node_t* wsdl_axiom,
    axis2_bool_t is_version1_wsdl)
{
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t* binding_node = NULL;
    axutil_hash_t* policies_hash = NULL;

    policies_hash = axutil_hash_make(env);

    if (wsf_wsdl_util_get_binding_node(env,
                                       wsdl_axiom,
                                       is_version1_wsdl,
                                       service_name,
                                       port_name,
                                       &binding_node))
    {

        if (wsf_wsdl_util_get_all_policies(env, 
                                           wsdl_axiom,
                                           binding_node,
                                           is_version1_wsdl,
                                           &policies_hash))
        {

            status = wsf_wsdl_util_configure_security_for_service(env,
                                                                  script_service_user_options,
                                                                  policies_hash,
                                                                  service,
                                                                  worker_conf_ctx);
        }
    }

    return status;
}


axis2_status_t
wsf_wsdl_util_configure_security_for_service(
    const axutil_env_t* env, 
    axutil_hash_t* script_client_options_hash, 
    axutil_hash_t* policies_hash,
    axis2_svc_t* svc,
    axis2_conf_ctx_t* worker_conf_ctx)
{
    axis2_char_t* policy_xml_str = NULL;
    axutil_hash_t* policy_hash = NULL;
    axutil_hash_t* security_token_hash = NULL;
    axiom_node_t* input_policy_node_axiom = NULL;
    axiom_node_t* binding_policy_node_axiom = NULL;
    neethi_policy_t* merged_neethi_policy = NULL;
    axis2_status_t success = AXIS2_FAILURE;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if (script_client_options_hash)
    {
        policy_xml_str = (axis2_char_t*)axutil_hash_get(script_client_options_hash, 
            WSF_WSDL_HK_POLICY_STRING, 
            AXIS2_HASH_KEY_STRING);
        policy_hash = (axutil_hash_t*)axutil_hash_get(script_client_options_hash, 
            WSF_WSDL_HK_POLICY_HASH, 
            AXIS2_HASH_KEY_STRING);
        security_token_hash = (axutil_hash_t*)axutil_hash_get(script_client_options_hash, 
            WSF_WSDL_HK_SECURITY_TOKEN, 
            AXIS2_HASH_KEY_STRING);
    }

    if (policy_xml_str)
    {
        success = wsf_wsdl_util_policy_from_xml_string(env, 
            policy_xml_str, 
            &input_policy_node_axiom);
    }
    else if (policy_hash)
    {
        success = wsf_wsdl_util_policy_from_options_hash(env, 
            policy_hash, 
            &input_policy_node_axiom);
    }
    /*else if (wsdl_policy_hash)
    {
        success = wsf_wsdl_util_policy_from_wsdl_policy_hash(env, 
            wsdl_policy_hash, 
            &input_policy_node_axiom,
            &binding_policy_node_axiom);
    }*/
    else if (policies_hash) /* TODO: correct this condition, as of now always security will be enabled */
    {
        success = AXIS2_SUCCESS;
    }
    else 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "No policies found! so security is not added");
        return AXIS2_SUCCESS; /* this is not a failure case, simply security is ommitted */
    }

    if (success)
    {
        success = AXIS2_FAILURE;

        if (security_token_hash)
        {
            axis2_char_t* op_name = NULL;
            /* loop policies hash */
            axutil_hash_index_t* hi = NULL;
            void* val = NULL;
  
            for (hi = axutil_hash_first(policies_hash, env); hi; hi = axutil_hash_next(env, hi)) 
            {
                axutil_hash_t* wsdl_policy_hash = NULL;
                axis2_ssize_t size;
                op_name = NULL;
                axutil_hash_this(hi, (void*)&op_name, &size, &val);
                wsdl_policy_hash = (axutil_hash_t *)val;

                if (!(op_name && wsdl_policy_hash))
                {
                    continue;
                }
           
                success = wsf_wsdl_util_policy_from_wsdl_policy_hash(env, 
                                                                     wsdl_policy_hash, 
                                                                     &input_policy_node_axiom,
                                                                     &binding_policy_node_axiom);
                if (success)
                {                                                  
                    if (wsf_wsdl_util_create_merged_neethi_policy(env,
                                                                  input_policy_node_axiom,
                                                                  binding_policy_node_axiom,
                                                                  &merged_neethi_policy))
                    {
                        if (wsf_wsdl_util_insert_policy_to_svc(env,
                                                               merged_neethi_policy,
                                                               svc,
                                                               op_name))
                        {
                            if (wsf_wsdl_util_add_security_to_svc_configuration(env, 
                                                                                security_token_hash, 
                                                                                svc))
                            {	
                                axis2_conf_t *conf = NULL;
                                conf = axis2_conf_ctx_get_conf (worker_conf_ctx, env);
                                wsf_wsdl_util_engage_module (conf, 
                                                             WSF_WSDL_MODULE_SECURITY, 
                                                             env, 
                                                             svc);
                            }
                        }
                    }
                }
            }
        }
    }

    return success;
}


axis2_status_t
wsf_wsdl_util_insert_policy_to_svc(
    const axutil_env_t* env, 
    neethi_policy_t* merged_input_neethi_policy,
    axis2_svc_t* svc,
    axis2_char_t* op_name)
{
    axis2_desc_t *desc = NULL;
    axis2_policy_include_t *policy_include = NULL;
    axis2_op_t *op = NULL;

    op = axis2_svc_get_op_with_name (svc, env, op_name);
    if (!op) 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "Service is NULL");
        return AXIS2_FAILURE;
    }

    desc = axis2_op_get_base (op, env);
    if (!desc) 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "Description is NULL");
        return AXIS2_FAILURE;
    }

    policy_include = axis2_desc_get_policy_include (desc, env);
    if (!policy_include) 
    {
        AXIS2_LOG_DEBUG_MSG(env->log, "Policy Include is NULL");
        return AXIS2_FAILURE;
    }

    return axis2_policy_include_add_policy_element (policy_include, env,
        AXIS2_SERVICE_POLICY, 
        merged_input_neethi_policy);
}

axis2_status_t
wsf_wsdl_util_add_security_to_svc_configuration(
    const axutil_env_t* env,
    axutil_hash_t* security_token_hash,
    axis2_svc_t* svc)
{
    rampart_context_t* rampart_ctx = NULL;
    axutil_param_t *security_param = NULL;

    rampart_ctx = rampart_context_create(env);

    wsf_wsdl_util_set_security_token_options_to_rampart_ctx (env, security_token_hash, rampart_ctx);

    security_param = axutil_param_create (env, WSF_WSDL_RAMPART_CONFIGURATION, (void *)rampart_ctx);

    return axis2_svc_add_param (svc, env, security_param);
}

axis2_status_t
wsf_wsdl_util_engage_module(
    axis2_conf_t * conf,
    axis2_char_t * module_name,
    const axutil_env_t * env,
    axis2_svc_t * svc)
{
    axis2_module_desc_t *module = NULL;
    axutil_qname_t *mod_qname = NULL;
    axis2_phase_resolver_t *phase_resolver = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    mod_qname = axutil_qname_create (env, module_name, NULL, NULL);
    module = axis2_conf_get_module (conf, env, mod_qname);
    
    if (module) 
    {
        status = axis2_svc_engage_module (svc, env, module, conf);
        
        if (!status) 
        {
            phase_resolver = axis2_phase_resolver_create_with_config (env, conf);
            
            if (!phase_resolver) 
            {
                AXIS2_LOG_DEBUG_MSG(env->log, "phase resolver is NULL");
                return AXIS2_FAILURE;
            }
            status = axis2_phase_resolver_engage_module_to_svc (phase_resolver,
                                                                env, 
                                                                svc, 
                                                                module);
        }
    }
    return status;
}

void wsf_wsdl_attach_xsd_imports(const axutil_env_t *env, axiom_node_t *wsdl_type_om, axiom_node_t *schema_om,
                                axis2_char_t *relative_url, axutil_hash_t *already_imported_xsds);

axiom_node_t*
wsf_wsdl_clear_xsd_imports(const axutil_env_t *env, axiom_node_t *wsdl_om, axis2_char_t *relative_url) {
    axutil_hash_t *already_imported_xsds = NULL;
    axiom_node_t *wsdl_type_om = NULL;

    already_imported_xsds = axutil_hash_make(env);

    /* iterate types information from the very wsdl */
    for(wsdl_type_om = axiom_node_get_first_child(wsdl_om, env);
            wsdl_type_om;
            wsdl_type_om = axiom_node_get_next_sibling(wsdl_type_om, env))
    {
        if(axiom_node_get_node_type(wsdl_type_om, env) == AXIOM_ELEMENT) {
            axis2_char_t *local_name = NULL;
            axiom_element_t *type_element = NULL;

            type_element = (axiom_element_t*)axiom_node_get_data_element(wsdl_type_om, env);
            local_name = axiom_element_get_localname(type_element, env);
            
            if(axutil_strcmp(local_name, "types") == 0) {
                axiom_node_t *wsdl_type_child_om = NULL;
                axiom_element_t *wsdl_type_child_ele = NULL;

                for(wsdl_type_child_om = axiom_node_get_first_child(wsdl_type_om, env);
                        wsdl_type_child_om;
                        wsdl_type_child_om = axiom_node_get_next_sibling(wsdl_type_child_om, env)) {
                    
                    if(axiom_node_get_node_type(wsdl_type_child_om, env) == AXIOM_ELEMENT) {
                        axis2_char_t *schema_local_name = NULL;
                        wsdl_type_child_ele = 
                            (axiom_element_t*) axiom_node_get_data_element(wsdl_type_child_om, env);
                        schema_local_name = axiom_element_get_localname(wsdl_type_child_ele, env);

                        if(axutil_strcmp(schema_local_name, "schema") == 0) {
                            wsf_wsdl_attach_xsd_imports(env, wsdl_type_om, wsdl_type_child_om,
                                relative_url, already_imported_xsds);
                        }
                    }
                }
            }
        }
    }
    axutil_hash_free(already_imported_xsds, env);
    return wsdl_om;
}

void
wsf_wsdl_get_wsdl_imports(const axutil_env_t *env, axiom_node_t *wsdl_om, axis2_char_t *relative_url, 
        axutil_hash_t *already_imported_wsdls, axutil_array_list_t *imported_wsdl_om_arr);

axiom_node_t*
wsf_wsdl_clear_wsdl_imports(const axutil_env_t *env, axiom_node_t *wsdl_om, axis2_char_t *relative_url) {

    axutil_hash_t *already_imported_wsdls = NULL;
    axutil_array_list_t *imported_wsdl_om_arr = NULL;
    axiom_node_t *new_wsdl_om = NULL;
    axiom_element_t *new_wsdl_ele = NULL;
    axutil_qname_t *tns_qname = NULL;
    axis2_char_t *root_tns_value = NULL;
    axiom_namespace_t *root_tns_ns = NULL;
    axutil_hash_t *namespace_map = NULL;
    int prefix_count = 100; /* when giving numbering we start with 100 for safety */
    int imported_count = 0;

    /* types node */
    axiom_node_t *new_wsdl_type_om = NULL;
    axiom_node_t *import_nodes = NULL;

    int i = 0;
    
    already_imported_wsdls = axutil_hash_make(env);
    imported_wsdl_om_arr = axutil_array_list_create(env, 10);

    wsf_wsdl_get_wsdl_imports(env, wsdl_om, relative_url, already_imported_wsdls, imported_wsdl_om_arr);

    imported_count = axutil_array_list_size(imported_wsdl_om_arr, env);

    if(imported_count == 0) {
        return wsdl_om;
    }

    axutil_hash_free(already_imported_wsdls, env);

    /* we are doing changes to the current wsdl itself */
    new_wsdl_om = wsdl_om;

    new_wsdl_ele = (axiom_element_t*)axiom_node_get_data_element(new_wsdl_om, env);
    tns_qname = axutil_qname_create(env, "targetNamespace", NULL, NULL);
    root_tns_value = axiom_element_get_attribute_value(new_wsdl_ele, env, tns_qname);
    axutil_qname_free(tns_qname, env);

    root_tns_ns = axiom_namespace_create(env, root_tns_value, "tns");
    axiom_element_declare_namespace(new_wsdl_ele, env, new_wsdl_om, root_tns_ns);

    namespace_map = axutil_hash_make(env);

    /* iterate types information from all wsdls */
    for(new_wsdl_type_om = axiom_node_get_first_child(new_wsdl_om, env);
            new_wsdl_type_om;
            new_wsdl_type_om = axiom_node_get_next_sibling(new_wsdl_type_om, env))
    {
        if(axiom_node_get_node_type(new_wsdl_type_om, env) == AXIOM_ELEMENT) {
            axis2_char_t *local_name = NULL;
            axiom_element_t *type_element = NULL;

            type_element = (axiom_element_t*)axiom_node_get_data_element(new_wsdl_type_om, env);
            local_name = axiom_element_get_localname(type_element, env);
           
            if(axutil_strcmp(local_name, "types") == 0) {
                break;
            }
        }
    }

    if(!new_wsdl_type_om) {
        axiom_namespace_t *wsdl_ns = NULL;
        axiom_element_t *type_element = NULL;

        wsdl_ns = axiom_namespace_create(env, "http://schemas.xmlsoap.org/wsdl/", "wsdl");
        type_element = axiom_element_create(env, NULL, "types", wsdl_ns, &new_wsdl_type_om);

        axiom_node_add_child(new_wsdl_om, env, new_wsdl_type_om);
    }


    /* iterate import information from all the wsdls */
    for(i = 0; i < imported_count; i ++) {
        axiom_node_t *imported_wsdl_om = NULL;
        axiom_element_t *imported_wsdl_ele = NULL;
        axiom_node_t *imported_wsdl_child_om = NULL;
        axiom_element_t *imported_wsdl_child_ele = NULL;
        axiom_children_iterator_t *child_itr = NULL;

        
        imported_wsdl_om = axutil_array_list_get(imported_wsdl_om_arr, env, i);
        imported_wsdl_ele = (axiom_element_t*)axiom_node_get_data_element(imported_wsdl_om, env);

        child_itr = axiom_element_get_children(imported_wsdl_ele, env, imported_wsdl_om);

        axiom_children_iterator_reset(child_itr, env);

        while(child_itr && axiom_children_iterator_has_next(child_itr, env)) {
            imported_wsdl_child_om = axiom_children_iterator_next(child_itr, env);
            if(axiom_node_get_node_type(imported_wsdl_child_om, env) == AXIOM_ELEMENT) {
                axis2_char_t *imported_wsdl_child_name = NULL;

                imported_wsdl_child_ele = axiom_node_get_data_element(imported_wsdl_child_om, env);
                imported_wsdl_child_name = axiom_element_get_localname(imported_wsdl_child_ele, env);

                if(axutil_strcmp(imported_wsdl_child_name, "service") == 0) {
                    /* found the service node */

                    axiom_node_t *service_child_om = NULL;
                    for(service_child_om = axiom_node_get_first_child(imported_wsdl_child_om, env);
                            service_child_om;
                            service_child_om = axiom_node_get_next_sibling(service_child_om, env)) {
                        if(axiom_node_get_node_type(service_child_om, env) == AXIOM_ELEMENT) {
                            axiom_element_t *service_child_ele = NULL;
                            axis2_char_t *service_child_name = NULL;

                            service_child_ele = 
                              (axiom_element_t*)axiom_node_get_data_element(service_child_om, env);
                            service_child_name = axiom_element_get_localname(service_child_ele, env);

                            if(axutil_strcmp(service_child_name, "port") == 0) {
                                axis2_char_t *binding_value = NULL;
                                axis2_char_t *binding_localvalue = NULL;
                                axiom_attribute_t *binding_attr = NULL;
                                axutil_qname_t *binding_qname = NULL;

                                binding_qname = axutil_qname_create(env, "binding", NULL, NULL);
                                binding_attr = axiom_element_get_attribute(service_child_ele, env, binding_qname);
                                axutil_qname_free(binding_qname, env);
                               
                                binding_value = axiom_attribute_get_value(binding_attr, env);
                                binding_localvalue = strstr(binding_value, ":");
                                if(binding_localvalue) {
                                    axis2_char_t *new_binding_value = NULL;

                                    new_binding_value = axutil_strcat(env, "tns", binding_localvalue, NULL);
                                    axiom_attribute_set_value(binding_attr, env, new_binding_value);

                                    AXIS2_FREE(env->allocator, new_binding_value);
                                }
                            }
                        }
                    }
                    axiom_node_detach(imported_wsdl_child_om, env);
                    axiom_node_add_child(new_wsdl_om, env, imported_wsdl_child_om);
                }

                if(axutil_strcmp(imported_wsdl_child_name, "binding") == 0) {
                    /* found the binding node */
                    axis2_char_t *type_value = NULL;
                    axis2_char_t *type_localvalue = NULL;
                    axiom_attribute_t *type_attr = NULL;
                    axutil_qname_t *type_qname = NULL;

                    type_qname = axutil_qname_create(env, "type", NULL, NULL);
                    type_attr = axiom_element_get_attribute(imported_wsdl_child_ele, env, type_qname);
                    axutil_qname_free(type_qname, env);
                   
                    type_value = axiom_attribute_get_value(type_attr, env);
                    type_localvalue = strstr(type_value, ":");
                    if(type_localvalue) {
                        axis2_char_t *new_type_value = NULL;

                        new_type_value = axutil_strcat(env, "tns", type_localvalue, NULL);
                        axiom_attribute_set_value(type_attr, env, new_type_value);

                        AXIS2_FREE(env->allocator, new_type_value);
                    }

                    axiom_node_detach(imported_wsdl_child_om, env);
                    axiom_node_add_child(new_wsdl_om, env, imported_wsdl_child_om);
                }

                if(axutil_strcmp(imported_wsdl_child_name, "portType") == 0) {
                    /* found the port type node */

                    axiom_node_t *porttype_child_om = NULL;
                    for(porttype_child_om = axiom_node_get_first_child(imported_wsdl_child_om, env);
                            porttype_child_om;
                            porttype_child_om = axiom_node_get_next_sibling(porttype_child_om, env)) {
                        if(axiom_node_get_node_type(porttype_child_om, env) == AXIOM_ELEMENT) {
                            axiom_element_t *porttype_child_ele = NULL;
                            axis2_char_t *porttype_child_name = NULL;

                            porttype_child_ele = 
                              (axiom_element_t*)axiom_node_get_data_element(porttype_child_om, env);
                            porttype_child_name = axiom_element_get_localname(porttype_child_ele, env);

                            if(axutil_strcmp(porttype_child_name, "operation") == 0) {
                                axiom_element_t *operation_child_ele = NULL;
                                axiom_node_t *operation_child_om = NULL;
                                axis2_char_t *operation_child_name = NULL;

                                for(operation_child_om = axiom_node_get_first_child(porttype_child_om, env);
                                        operation_child_om;
                                        operation_child_om = axiom_node_get_next_sibling(operation_child_om, env)) {
                                    if(axiom_node_get_node_type(operation_child_om, env) == AXIOM_ELEMENT) {
                                        operation_child_ele = 
                                          (axiom_element_t*)axiom_node_get_data_element(operation_child_om, env);
                                        operation_child_name = axiom_element_get_localname(operation_child_ele, env);

                                        if(axutil_strcmp(operation_child_name, "input") == 0 ||
                                                axutil_strcmp(operation_child_name, "output") == 0) {

                                            axis2_char_t *message_value = NULL;
                                            axis2_char_t *message_localvalue = NULL;
                                            axiom_attribute_t *message_attr = NULL;
                                            axutil_qname_t *message_qname = NULL;

                                            message_qname = axutil_qname_create(env, "message", NULL, NULL);
                                            message_attr = axiom_element_get_attribute(operation_child_ele, env, message_qname);
                                            axutil_qname_free(message_qname, env);
                                           
                                            message_value = axiom_attribute_get_value(message_attr, env);
                                            message_localvalue = strstr(message_value, ":");
                                            if(message_localvalue) {
                                                axis2_char_t *new_message_value = NULL;

                                                new_message_value = axutil_strcat(env, "tns", message_localvalue, NULL);
                                                axiom_attribute_set_value(message_attr, env, new_message_value);

                                                AXIS2_FREE(env->allocator, new_message_value);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    axiom_node_detach(imported_wsdl_child_om, env);
                    axiom_node_add_child(new_wsdl_om, env, imported_wsdl_child_om);

                }

                if(axutil_strcmp(imported_wsdl_child_name, "message") == 0) {
                    /* found the port type node */

                    axiom_node_t *message_child_om = NULL;
                    for(message_child_om = axiom_node_get_first_child(imported_wsdl_child_om, env);
                            message_child_om;
                            message_child_om = axiom_node_get_next_sibling(message_child_om, env)) {
                        if(axiom_node_get_node_type(message_child_om, env) == AXIOM_ELEMENT) {
                            axiom_element_t *message_child_ele = NULL;
                            axis2_char_t *message_child_name = NULL;

                            message_child_ele = 
                              (axiom_element_t*)axiom_node_get_data_element(message_child_om, env);
                            message_child_name = axiom_element_get_localname(message_child_ele, env);

                            if(axutil_strcmp(message_child_name, "part") == 0) {

                                axutil_qname_t *type_qname = NULL;
                                axiom_attribute_t *type_attr = NULL;

                                axiom_attribute_t *element_attr = NULL;
                                axutil_qname_t *element_qname = NULL;
                                
                                type_qname = axutil_qname_create(env, "type", NULL, NULL);
                                type_attr = axiom_element_get_attribute(message_child_ele, env, type_qname);
                                if(type_attr) {
                                    axis2_char_t *type_value = NULL;
                                    axis2_char_t *type_localvalue = NULL;
                                    axis2_char_t *type_prefix = NULL;
                                    axis2_char_t *new_prefix = NULL;

                                    axis2_char_t *type_ns = NULL;
                                    axis2_char_t *new_type_value = NULL;

                                    type_value = axiom_attribute_get_value(type_attr, env);
                                    type_localvalue = strstr(type_value, ":");
                                    if(type_localvalue) {

                                        axis2_char_t *prefix = NULL;
                                        axiom_namespace_t *element_ns_namespace = NULL;

                                        *type_localvalue = '\0';
                                        prefix = type_value;
                                        
                                        element_ns_namespace = axiom_element_find_namespace_uri(imported_wsdl_ele, env, prefix, imported_wsdl_om);
                                        *type_localvalue = ':';

                                        type_ns = axiom_namespace_get_uri(element_ns_namespace, env);

                                    }
                                    else {
                                        axutil_qname_t *xmlns_qname = NULL;

                                        type_localvalue = type_value;
                                        xmlns_qname = axutil_qname_create(env, "xmlns", NULL, NULL); 
                                        type_ns = axiom_element_get_attribute_value(imported_wsdl_ele, env, xmlns_qname);
                                    }

                                    new_prefix = axutil_hash_get(namespace_map, type_ns, AXIS2_HASH_KEY_STRING);
                                    if(!new_prefix) {
                                        new_prefix = AXIS2_MALLOC(env->allocator, sizeof(axis2_char_t)*64);
                                        sprintf(new_prefix, "ns%d", prefix_count ++);
                                        axutil_hash_set(namespace_map, type_ns, AXIS2_HASH_KEY_STRING, new_prefix);
                                    }
                                    new_type_value = axutil_strcat(env, new_prefix, type_localvalue, NULL);
                                    axiom_attribute_set_value(type_attr, env, new_type_value);

                                    AXIS2_FREE(env->allocator, new_type_value);
                                    AXIS2_FREE(env->allocator, new_prefix);
                                }
                                axutil_qname_free(type_qname, env);
                                
                                /* now go for the element attribute */
                                element_qname = axutil_qname_create(env, "element", NULL, NULL);
                                element_attr = axiom_element_get_attribute(message_child_ele, env, element_qname);
                                if(element_attr) {
                                    axis2_char_t *element_value = NULL;
                                    axis2_char_t *element_localvalue = NULL;
                                    axis2_char_t *element_prefix = NULL;
                                    axis2_char_t *new_prefix = NULL;

                                    axis2_char_t *element_ns = NULL;
                                    axis2_char_t *new_element_value = NULL;

                                    element_value = axiom_attribute_get_value(element_attr, env);
                                    element_localvalue = strstr(element_value, ":");
                                    if(element_localvalue) {
                                        axis2_char_t *prefix = NULL;
                                        axiom_namespace_t *element_ns_namespace = NULL;

                                        *element_localvalue = '\0';
                                        prefix = element_value;

                                        element_ns_namespace = axiom_element_find_namespace_uri(imported_wsdl_ele, env, prefix, imported_wsdl_om);
                                        *element_localvalue = ':';

                                        element_ns = axiom_namespace_get_uri(element_ns_namespace, env);

                                    }
                                    else {
                                        axutil_qname_t *xmlns_qname = NULL;

                                        element_localvalue = element_value;
                                        xmlns_qname = axutil_qname_create(env, "xmlns", NULL, NULL); 
                                        element_ns = axiom_element_get_attribute_value(imported_wsdl_ele, env, xmlns_qname);
                                    }

                                    new_prefix = axutil_hash_get(namespace_map, element_ns, AXIS2_HASH_KEY_STRING);
                                    if(!new_prefix) {
                                        new_prefix = AXIS2_MALLOC(env->allocator, sizeof(axis2_char_t)*64);
                                        sprintf(new_prefix, "ns%d", prefix_count ++);
                                        axutil_hash_set(namespace_map, element_ns, AXIS2_HASH_KEY_STRING, new_prefix);
                                    }
                                    new_element_value = axutil_strcat(env, new_prefix, element_localvalue, NULL);
                                    axiom_attribute_set_value(element_attr, env, new_element_value);

                                    AXIS2_FREE(env->allocator, new_element_value);
                                }
                                axutil_qname_free(element_qname, env);

                            }
                        }
                    }
                    axiom_node_detach(imported_wsdl_child_om, env);
                    axiom_node_add_child(new_wsdl_om, env, imported_wsdl_child_om);
;
                }
                if(axutil_strcmp(imported_wsdl_child_name, "types") == 0) {
                    /* found the port type node */

                    axiom_node_t *types_child_om = NULL;
                    for(types_child_om = axiom_node_get_first_child(imported_wsdl_child_om, env);
                            types_child_om;
                            types_child_om = axiom_node_get_next_sibling(types_child_om, env)) {
                        
                        if(axiom_node_get_node_type(types_child_om, env) == AXIOM_ELEMENT) {
                            /* this is for all the schema */

                            axiom_node_detach(types_child_om, env);

                            axiom_node_add_child(new_wsdl_type_om, env, types_child_om);
                        }
                    }
                }
            }
        }
    }
    return new_wsdl_om;
}

axis2_char_t *
wsf_wsdl_normalize_url(const axutil_env_t *env, axis2_char_t *url);

void
wsf_wsdl_get_wsdl_imports(const axutil_env_t *env, axiom_node_t *wsdl_om, axis2_char_t *relative_url, 
        axutil_hash_t *already_imported_wsdls, axutil_array_list_t *imported_wsdl_om_arr) {

    axiom_element_t *wsdl_ele = NULL;
    axiom_children_iterator_t *wsdl_childs_itr = NULL;

    int relative_url_len = 0;
    char *cp = NULL;
    axis2_char_t *relative_dir = NULL; /* we does keep the last '/' or '\\' here */


    /* now find the directory path of the current wsdl relative or absolute url */
    relative_url_len = axutil_strlen(relative_url);


    /* find the lastmost "/" or "\" character */
    for(cp = relative_url + relative_url_len -1; *cp != '/' && *cp != '\\' && cp >= relative_url; cp --);

    if(*cp == '/' || *cp == '\\') {
		char tmp_c;
        cp ++;
        tmp_c = *cp;
        
        *cp = '\0';
        relative_dir = axutil_strdup(env, relative_url);

        *cp = tmp_c;
    }
    else {
        /* if no / or \\ then the wsdl dir should be current directory */
        relative_dir = axutil_strdup(env, "./");
    }
    

    /* retrieve the child iterator */
    if(axiom_node_get_node_type(wsdl_om, env) == AXIOM_ELEMENT) {
        wsdl_ele = (axiom_element_t*)axiom_node_get_data_element(wsdl_om, env);
    }

    if(!wsdl_ele) {
        return;
    }
    wsdl_childs_itr = axiom_element_get_children(wsdl_ele, 
											      env,
											      wsdl_om);


    /* iterate through childs */
    while (wsdl_childs_itr && axiom_children_iterator_has_next(wsdl_childs_itr, env))
    {
        axiom_node_t *wsdl_child_om = NULL;
        axiom_element_t *wsdl_child_ele = NULL;
        axis2_char_t *wsdl_child_name = NULL;

	    wsdl_child_om = (axiom_node_t*)axiom_children_iterator_next(wsdl_childs_itr, env);
        if(axiom_node_get_node_type(wsdl_child_om, env) == AXIOM_ELEMENT) {
	        wsdl_child_ele = (axiom_element_t*)axiom_node_get_data_element(wsdl_child_om, env);
            wsdl_child_name = axiom_element_get_localname(wsdl_child_ele, env);

            /* iterate through all the imports */
            if(axutil_strcmp(wsdl_child_name, "import") == 0|| 
                    axutil_strcmp(wsdl_child_name, "include") == 0) {
                axutil_qname_t *location_qname = NULL;
                axiom_attribute_t *location_attri = NULL;
                axis2_char_t *imported_location = NULL;

                /* get the location attribute */
                location_qname = axutil_qname_create(env, "location", NULL, NULL);
                location_attri = axiom_element_get_attribute(wsdl_child_ele, env, location_qname);

                if(location_attri) {
                    imported_location = axiom_attribute_get_value(location_attri, env);
                }
                if(imported_location) {
                    if(strncmp(imported_location, "http://", 7) == 0 ||
                         strncmp(imported_location, "https://", 8) == 0) {
                         /* then this is a absolute URL and doesn't need to derive again.. */
                    }
                    else {
                        axis2_char_t *tmp_relative_url = NULL;
                        tmp_relative_url = axutil_strcat(env, relative_dir, imported_location, NULL);
                        imported_location = wsf_wsdl_normalize_url(env, tmp_relative_url);
                        AXIS2_FREE(env->allocator, tmp_relative_url);
                    }
                    
                    if(axutil_hash_get(already_imported_wsdls, imported_location, AXIS2_HASH_KEY_STRING) == NULL) {
                        axiom_node_t *imported_node = NULL;
                        axutil_array_list_t *recursive_imported_arr = NULL;
                        
                        /* updating the hash */
                        axutil_hash_set(already_imported_wsdls, imported_location, AXIS2_HASH_KEY_STRING, (void*)1);
                        
                        imported_node = wsf_wsdl_util_deserialize_file(env, imported_location);

                        axutil_array_list_add(imported_wsdl_om_arr, env, imported_node);

                        wsf_wsdl_get_wsdl_imports(env, imported_node, imported_location, 
                                    already_imported_wsdls, imported_wsdl_om_arr);
                    }
                }
                axutil_qname_free(location_qname, env);

                axiom_node_free_tree(wsdl_child_om, env);
            }
        }
    }
}

axis2_char_t *
wsf_wsdl_normalize_url(const axutil_env_t *env, axis2_char_t *url) {
    axis2_char_t *cp = NULL;
    axis2_char_t *token = NULL;
    /* i keeps the token count */
    int i = 0;
    int j = 0;
    /**
     * here 0 is for before finding any named component
     * 1 is for after finding some named component
     */
    int state = 0;

    /* tokens array */
    axutil_array_list_t *tokens_arr = NULL;
    int size = 0;

    /* to store new url */
    axis2_char_t *new_url = NULL;
    new_url = (axis2_char_t*) AXIS2_MALLOC(env->allocator, 
                sizeof(axis2_char_t)*axutil_strlen(url) + 1);

    tokens_arr = axutil_array_list_create(env, 10);

    for(cp = url, token = url, i = 0;
            1 ; cp ++, i ++) {
        if(*cp == '\\' || *cp == '/') {
            *cp = '\0';
            /* for each token in the url */
            if(state == 0) {
                if(axutil_strcmp(token, "..") != 0 && 
                    axutil_strcmp(token, ".") != 0 &&
                    axutil_strcmp(token, "") != 0) {
                    state = 1;
                }
            }
            else if(state == 1) {
                if(axutil_strcmp(token, "..")) {
                    for(j = i -1; j >= 0; j --) {
                        axis2_char_t *early_token = NULL;

                        early_token = axutil_array_list_get(tokens_arr, env, j);
                        if(early_token != NULL &&
                            axutil_strcmp(early_token, "..") != 0 && /* this should not occur */
                            axutil_strcmp(early_token, ".") != 0 &&
                            axutil_strcmp(early_token, "") != 0) {
                           
                            /* so we found j is something we can neutralize i */
                            axutil_array_list_set(tokens_arr, env, j, 0);
                            axutil_array_list_set(tokens_arr, env, i, 0);
                            break;
                        }
                    }
                }
            }
            axutil_array_list_add(tokens_arr, env, token);
            token = cp + 1;
        }
        else if(*cp == '\0') {
            axutil_array_list_add(tokens_arr, env, token);
            break;
        }
    }

    cp = new_url;
    size = axutil_array_list_size(tokens_arr, env);
    for(i = 0; i < size; i ++) {
        axis2_char_t *next_token = NULL;

        next_token = axutil_array_list_get(tokens_arr, env, i);
        if(next_token) {
            int next_token_size = axutil_strlen(next_token);

            strcpy(cp, next_token);

            cp += next_token_size;
            if(i != size -1 ) {
                *cp = '/';
                cp ++;
            }
        }
    }

    *cp = '\0';
    
    axutil_array_list_free(tokens_arr, env);

    return new_url;
}

void wsf_wsdl_attach_xsd_imports(const axutil_env_t *env, axiom_node_t *wsdl_type_om, axiom_node_t *schema_om,
                                axis2_char_t *relative_url, axutil_hash_t *already_imported_xsds) {

    axiom_element_t *schema_ele = NULL;
    axiom_children_iterator_t *schema_childs_itr = NULL;
    axutil_array_list_t *imported_nodes_arr = NULL;

    int relative_url_len = 0;
    char *cp = NULL;
    axis2_char_t *relative_dir = NULL; /* we does keep the last '/' or '\\' here */
    int i;


    /* now find the directory path of the current wsdl relative or absolute url */
    relative_url_len = axutil_strlen(relative_url);

    /* find the lastmost "/" or "\" character */
    for(cp = relative_url + relative_url_len -1; *cp != '/' && *cp != '\\' && cp >= relative_url; cp --);

    if(*cp == '/' || *cp == '\\') {
		char tmp_c;
        cp ++;
        tmp_c = *cp;
        
        *cp = '\0';
        relative_dir = axutil_strdup(env, relative_url);

        *cp = tmp_c;
    }
    else {
        /* if no / or \\ then the wsdl dir should be current directory */
        relative_dir = axutil_strdup(env, "./");
    }

    /* retrieve the child iterator */
    if(axiom_node_get_node_type(schema_om, env) == AXIOM_ELEMENT) {
        schema_ele = (axiom_element_t*)axiom_node_get_data_element(schema_om, env);
    }

    if(!schema_ele) {
        return;
    }
    schema_childs_itr = axiom_element_get_children(schema_ele, 
											      env,
											      schema_om);

    imported_nodes_arr = axutil_array_list_create(env, 10);

    /* iterate through childs */
    while (schema_childs_itr && axiom_children_iterator_has_next(schema_childs_itr, env))
    {
        axiom_node_t *schema_child_om = NULL;
        axiom_element_t *schema_child_ele = NULL;
        axis2_char_t *schema_child_name = NULL;

	    schema_child_om = (axiom_node_t*)axiom_children_iterator_next(schema_childs_itr, env);
        if(axiom_node_get_node_type(schema_child_om, env) == AXIOM_ELEMENT) {
	        schema_child_ele = (axiom_element_t*)axiom_node_get_data_element(schema_child_om, env);
            schema_child_name = axiom_element_get_localname(schema_child_ele, env);

            /* iterate through all the imports */
            if(axutil_strcmp(schema_child_name, "import")  == 0 || 
                    axutil_strcmp(schema_child_name, "include") == 0) {
                axutil_qname_t *location_qname = NULL;
                axiom_attribute_t *location_attri = NULL;
                axis2_char_t *imported_location = NULL;

                /* get the location attribute */
                location_qname = axutil_qname_create(env, "schemaLocation", NULL, NULL);
                location_attri = axiom_element_get_attribute(schema_child_ele, env, location_qname);

                if(location_attri) {
                    imported_location = axiom_attribute_get_value(location_attri, env);
                }
                if(imported_location) {
                    if(strncmp(imported_location, "http://", 7) == 0 ||
                        strncmp(imported_location, "https://", 8) == 0) {
                        /* then this is a absolute URL and doesn't need to derive again.. */
                    }
                    else {
                        axis2_char_t *tmp_relative_url = NULL;
                        tmp_relative_url = axutil_strcat(env, relative_dir, imported_location, NULL);
                        imported_location = wsf_wsdl_normalize_url(env, tmp_relative_url);
                        AXIS2_FREE(env->allocator, tmp_relative_url);
                    }
                    
                    if(axutil_hash_get(already_imported_xsds, imported_location, AXIS2_HASH_KEY_STRING) == NULL) {
                        axiom_node_t *imported_node = NULL;
                        axutil_array_list_t *recursive_imported_arr = NULL;
                        
                        /* updating the hash */
                        axutil_hash_set(already_imported_xsds, imported_location, AXIS2_HASH_KEY_STRING, (void*)1);
                        
                        imported_node = wsf_wsdl_util_deserialize_file(env, imported_location);


                        wsf_wsdl_attach_xsd_imports(env, wsdl_type_om, imported_node,
                                imported_location, already_imported_xsds);
                        axiom_node_add_child(wsdl_type_om, env, imported_node);

                        /* updating the imported_nodes */
                        axutil_array_list_add(imported_nodes_arr, env, schema_child_om);
                    }
                    else {
                        /* the location was already added */
                        /* updating the imported_nodes */
                        axutil_array_list_add(imported_nodes_arr, env, schema_child_om);
                    }
                }
                axutil_qname_free(location_qname, env);
            }
        }
    }

    for(i = 0; i < axutil_array_list_size(imported_nodes_arr, env); i ++) {
        axiom_node_t *imported_node = NULL;

        imported_node = axutil_array_list_get(imported_nodes_arr, env, i);
        axiom_node_free_tree(imported_node, env);
    }

}
