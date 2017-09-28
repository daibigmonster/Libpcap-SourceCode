/*
 * 这里定义了一个网络接口的链表
 */
struct pcap_if{
    struct pcap_if *next;
    char* name;//name to hand to "pcap_open_live()"
    char* name;//textual description of interface,or null
    struct pcap_addr* addresses;
    bpf_u_int32 flags;
}

/*
 * Get a list of all capture sources that are up and that we can open.
 * Return -1 on error,0 otherwise
 * The list,as returned though "alldevsp",may be null if no interfaces were up and could be opened
 */
int
pcap_findalldevs(pcap_if_t **alldevsp,char *errbuf)
{
    size_t i;
    /*
     * 找到所有在当地我们能找到的网络接口
     */
    if(pcap_platform_finddevs(alldevsp,errrbuf)==-1)
        return (-1);
    
    /*
     *Ask each of the non_local_network_interface capture sources types what interfaces they have.
     */
    for(i=0;capture_source[i].findalldevs_op!=NULL;i++){
        if(capture_source_types[i].findalldevs_op(alldevsp,errbuf)==-1){
        /*
         * We had an error;free the list we've been
         * constructing.
         */
        if(*alldevsp!=NULL){
            pacp_freealldevs(*alldevsp);
            *alldevsp=NULL;
        }
        return (-1);
    }
}
    return (0);
}
