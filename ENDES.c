#include <stdio.h>
#include <math.h>
#define key 3000                                       /* 64-bit Key          */
static int m[4000][8],b[500][64],count;
static int L[32],R[32],K[16][48],F[32];


void convert_in(){/* Convert characters  */
    FILE *pi;                                            /* to "0" and "1" bit  */
    int i,j,x,p;                                         /* stream by ASCII     */
    pi=fopen("plaintext_for_Test","r");
    count=0;
    x=1;
    while (x!=EOF){
        x=getc(pi);                                  //Get the plaintext
        //printf("%d\n", x);
        p=1;
        for (i=0;i<=7;i++){
            m[count][i]=x & p;                     /* Each character      */
            p=p*2;                                 /* contains 8 bits     */
            if (m[count][i]!=0){
                m[count][i]=1;
            }
            b[count/8][8*(count%8)+i]=m[count][i]; /* Each block contains */
        }                                     /* 8 characters=64 bits*/
        count+=1;
    }
    count=count-2;
    while ((count%8)!= 0){                         /* Append "space": padding */
        for (i=0;i<=7;i++){                       /* character to obtain */
            b[count/8][8*(count%8)+i]=0;            /* a complete block    */
        }
        b[count/8][8*(count%8)+5]=1; //這啥？？？？？？？？？？
        count+=1;
    }
    fclose(pi);
}

void convert_out(){                                   /* Convert "0" and "1"  */                                                   /* bit stream to        */
    int i,x,p,j,n;                                      /* characters           */
    FILE *pi;                                            /* to "0" and "1" bit  */
    pi=fopen("output","w");
    for (i=0;i<count/8;i++)         //block數
        for (j=0;j<=7;j++)
            for (n=0;n<=7;n++)
                m[8*i+j][n]= b[i][8*j+n];
    for (i=0;i<count;i++){
        p=1;
        x=0;
        for (j=0;j<=7;j++){                  /* Convert binary to decimal int  */
            if(m[i][j] ==1)
                x+=pow(2, j);
        }
        printf("%c ", x);
        fprintf(pi, "%c", x);
        //putc(x, pi);
        //putchar(x);                                /* Output the ciphertext */
    }
    printf("\n");
    fclose(pi);
}


void IP(s,T)            // T=b                       /* Initial permutation and*/
int s,T[64];                                        /* inverse permutation    */
{ 
    int i,a[64],P[64];
    FILE *pi;

    if (s==1)
        pi=fopen("IP.dat","r");                         /* Initial permutation   */
    if (s==-1)                                         /* table and inverse     */
        pi=fopen("IP_inv.dat","r");                     /* initial permutation   */
                                                        /* table                 */
    for (i=0;i<=63;i++){
        fscanf(pi,"%d",&P[i]);
            a[i]=T[i];                        // a=b 即plaintext
        }
    for (i=0;i<=63;i++)
        T[i]=a[P[i]-1];                   //not sure
    fclose(pi);
}

void f(R,T)                                          /* Function f(Ri,Ki)     */
int R[],T[48];
{ 
    int E[48],Bit[48],S[8][4][16];
    int B[8][6],A[8][4],P[32],a[32],S_out[32],c[8];
    int i,j,p,x,y,n;
    FILE *pi;

    pi=fopen("E.dat","r");                          /* E table   */
    for (i=0;i<=47;i++)
        fscanf(pi,"%d", &Bit[i]);                   //32bits expand to 48bits
    for (i=0;i<=47;i++)
        E[i]=R[Bit[i]];                             //Expansion E function
    for (i=0;i<=7;i++)
        for (j=0;j<=5;j++)
            B[i][j]=E[i*6+j]^T[i*6+j];              /* E(Ri) XOR Ki =Bi      */
    fclose(pi);
    pi=fopen("sbox","r");                              /* S_box table           */
    for (i=0;i<=7;i++)
        for (j=0;j<=3;j++)
            for (n=0;n<=15;n++)
                fscanf(pi,"%d ",&S[i][j][n]);           //一般用8*8吧！～～
    for (i=0;i<=7;i++){                                 /* S_box algorithm       */
        p = B[i][1];
        B[i][1] = B[i][5];
        B[i][5] = p;
        c[i] = S[i][2*B[i][0]+B[i][5]][8*B[i][1]+4*B[i][2]+2*B[i][3]+1*B[i][4]];  //二進位轉10進位
        //printf("%d ", c[i]);
    }

    fclose(pi);
    pi=fopen("P.dat","r");                             /* Permutation table     */
    for (i=0;i<=7;i++){
        //p = 1; 0,8 0,4 0,2 0,1 1,0
        for (j=0;j<=3;j++){                            //取餘數 先取到的為bit數小的
            //printf("j[%d]: %2d, ", j, c[i]);
            if(c[i] > 0){
                S_out[4*i+(3-j)] = c[i]%2;              /* Output of s_box       */
                //p = p*2;
                c[i] = c[i]/2;
                //printf("%d ", S_out[4*i+(3-j)]);
            }
            else{
                S_out[4*i+(3-j)] = 0;
            }
        }
        //printf("\n");
    }
    /*for (i=0;i<=31;i++){
        //p = 1; 0,8 0,4 0,2 0,1 1,0
        printf("%d: %d\n", i, S_out[i]);
        if(i>1 && i%4==3)
            printf("\n");
    }*/
    for (i=0;i<=31;i++)
        fscanf(pi,"%d",&P[i]);
    for (i=0;i<=31;i++){
        R[i] = S_out[P[i]-1];                                /* Output of f(Ri,Ki)    */
        //printf("%2d: %2d,  ",P[i], S_out[P[i]-1]);
    }
    //printf("\n");
    fclose(pi);
}

void KEY(){                                           /* Key Calculation       */
    int i,j,p,x;
    static int LS[16],C[28],D[28],PC_1[56],PC_2[48],IK[64];
    int a[28],b[28];
    FILE *pi;

    p=1;
    for (i=0;i<=63;i++){                                /* 64-bit input Key      */
        IK[i]=p & key;
        if (IK[i]!=0)
            IK[i]=1;                                    //轉換成64bit的binary
        p*=2;
    }
    pi=fopen("keyshift","r");                          /* Key shift table       */
    for (i=0;i<=15;i++)
        fscanf(pi,"%d",&LS[i]);                        //16的round每次的位移量（只可能是1或2）
    fclose(pi);
    pi=fopen("PC_1.dat","r");                          /* PC_1 table(contraction_1)56*/
    for (i=0;i<=55;i++)
        fscanf(pi,"%d",&PC_1[i]);
    for (i=0;i<=27;i++){                               //contraction_1要分成左右兩邊28bits
        C[i] = IK[PC_1[i]-1];
        D[i] = IK[PC_1[i+28]-1];
    }
    fclose(pi);
    pi=fopen("PC_2.dat","r");                          /* PC_2 table(contraction_2)48*/
    for (i=0;i<=47;i++)
        fscanf(pi,"%d",&PC_2[i]);
    for (i=0;i<=15;i++){                               //16 rounds
        for (j=0;j<=27;j++){
            p = (j+LS[i])%28;                        //C,D做left circular1
            a[j] = C[p];
            b[j] = D[p];
        }
        for (j=0;j<=27;j++){                           //a,b 還給C,D 因為下ㄧround還要用
            C[j] = a[j];
            D[j] = b[j];
        }

        for (j=0;j<=47;j++){                          /* Output of Ki  23->47   */
            x = PC_2[j]-1;
            if(x > 27){
                K[i][j] = b[x-28];
            }
            else{
                K[i][j] = a[x];
            }
        }
    }
    fclose(pi);
}

int main(){
    int i,j,n;
    int temp[32];

    KEY();                                             /* Key Calculation       */
    convert_in();                                       /* Input the plaintext   */
    for (i=0;i<count/8;i++){                        /* ECB Mode  */
        IP(1,b[i]);            //pass by address       /* Initial permutation   */
        for (j=0;j<=31;j++){
            L[j] = b[i][j];                                 /* left and right parts  */
            R[j] = b[i][j+32];             //不確定b的直是否為位址
        }
        for (j=0;j<=15;j++){               /* round 0 to 15 */
            for (n=0;n<=31;n++){     /*swap right to left part*/
                temp[n] = R[n];
            }
            f(R,K[j]);              //pass by address
            for (n=0;n<=31;n++){    /*swap left to right part*/
                //printf("%2d: %d xor %d = %d\n", n,L[n],R[n], (L[n]^R[n]));
                R[n] = (L[n]^R[n]);
                L[n] = temp[n];
            }
            /*printf("\nR\n");
            for (size_t i = 0; i < 32; i++){
                printf("%zu: %2d, ", i, R[i]);
            }
            printf("\n");
            printf("\nL\n");
            for (size_t i = 0; i < 32; i++){
                printf("%zu: %2d, ", i, R[i]);
            }
            printf("\n");
            */
        }

        for (j=0;j<=31;j++){
            b[i][j]=R[j];
            b[i][j+32]=L[j];
        }
        IP(-1,b[i]);                                 /* Invers permutation    */
    }
    convert_out();                                    /* Output the ciphertext */
    return 0;
}
