void print_hex_ascii_line(const u_char* payload,int len,int offset)
{
    int i;
    int gap;
    const u_char *ch;
    printf("%05d   ",offset);
    ch=payload;
    for(i=0;i<len;i++)
    {
        printf("%02x ",*ch);//ye payload data ki hexa decimal value print krega
        ch++;
        if(i==7)
        printf(" "); //ye thoda output sahi aaye isliye
    }
    if(len < 8)
    {
        printf(" ");
    }
    //ye hexa gap jo bytes rhe gyi hain unhe fill krne ke liye
    if(len < 16)
    {
        gap=len-16;
        for(i=0;i<gap;i++)
        printf(" ");
    }
    printf(" ");
    ch=payload;//ascii format mein print krne ke liye yadi use print kr sakte hain toh
    for(i=0;i<len;i++)
    {
        if(isprint(*ch))
        printf("%c",*ch);
        else
        printf(".");
        ch++;
    }
    printf("\n");
    return;
}
void print_payload(const u_char *payload,int len)
{
    int len_rem=len;
    int line_width =16;
    int line_len;
    int offset=0;
    const u_char *ch=payload;
    if(len<=0)
    return;
    if(len<=16)
    {
        print_hex_ascii_line(payload,len,offset);
        return;
    }
    for(;;)
    {
        line_len=line_width%len_rem;
        print_hex_ascii_line(ch,line_len,offset);
        len_rem=len_rem-line_len;
        ch=ch+line_len;
        if(len_rem<=line_width)
        {
            print_hex_ascii_line(ch,len_rem,offset);
            break;
        }
    }
    return ;
}
