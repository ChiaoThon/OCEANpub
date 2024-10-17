/*
Authors: Qiao Zhang
Copyright:
Copyright (c) 2024 Qiao Zhang
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define SCI_HE
#define BITLEN_41
#include <iostream>
#include <fstream>
#include <thread>
#include "NonLinear/relu-field.h"
#include "LinearHE/conv-field.h"
#include "globals.h"

//selectively uncomment the following statement if you want to run the code beyond localhost, and then input the specific IP address of the server at the end of "***Argument Parsing***" part
//#define LAN_EXEC
//#define WAN_EXEC

//comment the following statement in ../src/LinearHE/defines-HE.h
//if you want to bypass the verification process: 
//#define DEBUG_EXEC

using namespace sci;
using namespace std;
using namespace seal;

/************* Data Configuration  **********/
/********************************************/
//default Conv structure
int image_h = 56;
int inp_chans = 64;
int filter_h = 3;
int out_chans = 64;
int stride = 1;
int pad_l = (filter_h-1)/2;
int pad_r = (filter_h-1)/2;
//the number of drelu to be computed
int num_relu = image_h*image_h*inp_chans;
//this choice is a trick as analyzed in CTF2
int filter_precision = 12;
//default networking and bitwidth configuration
int port = 32000;
int l = 41, b = 4;
string address;
bool localhost = true;
//set this variable to true to catch up with the computing process
bool verbose_info = true;

//this function performs MSB computing for each thread
void field_relu_thread(int tid, uint64_t* z, uint64_t* x, int lnum_relu) {
    ReLUFieldProtocol<NetIO, uint64_t>* relu_oracle;
    relu_oracle = new ReLUFieldProtocol<NetIO, uint64_t>(party, FIELD, ioArr[tid], l, b, prime_mod, otpackArr[tid]);
    relu_oracle->relu_pregen(z, x, lnum_relu);
    delete relu_oracle;
    return;
}

int main(int argc, char** argv) {

    /************* Argument Parsing  ************/
    /********************************************/
    ArgMapping amap;
    amap.arg("r", party, "Role of party: ALICE = server = 1; BOB = client = 2");
    amap.arg("p", port, "Port Number");
    amap.arg("l", l, "Bitlength of inputs");
    //Conv
    amap.arg("h", image_h, "Image Height/Width");
    amap.arg("f", filter_h, "Filter Height/Width");
    amap.arg("i", inp_chans, "Input Channels");
    amap.arg("o", out_chans, "Ouput Channels");
    amap.arg("s", stride, "stride");
    amap.arg("pl", pad_l, "Left Padding");
    amap.arg("pr", pad_r, "Right Padding");
    amap.arg("fp", filter_precision, "Filter Precision");   

    //this is the block length namely m that divides the whole bits
    //in millionaries' protocol of CrypTFlow2
    amap.arg("b", b, "Radix base");
    
    amap.arg("lo", localhost, "Localhost Run?");
    amap.parse(argc, argv);

    if(not localhost) {
#if defined(LAN_EXEC)
        address = "input.your.LAN.address";
#elif defined(WAN_EXEC)
        address = "input.your.WAN.address";
#endif
    } else {
        address = "127.0.0.1";
    }

    //update the numbers based on arg inputs
    num_relu = image_h*image_h*inp_chans;
    int pad_l = (filter_h-1)/2;
    int pad_r = (filter_h-1)/2;

    cout << "==================================================================" << endl;
    cout << "Role Coding: 1 is server; 2 is client" << endl;
    cout << "==================================================================" << endl;
    cout << "Role: " << party << " - Bitlength: " << bitlength
        << " - Image: " << image_h << "x" << image_h << "x" << inp_chans
        << " - Filter: " << filter_h << "x" << filter_h << "x" << out_chans
        << "\n- Stride: " << stride << "x" << stride
        << " - Padding: " << pad_l << "x" << pad_r
        << " - # Threads: " << numThreads << "\n- Radix Base: " << b
        << " - # DReLUs/MSBs: " << num_relu << endl;
    cout << "------------------------------------------------------------------" << endl;


    /************ Generate the Data **************/
    /********************************************/

    //define the data sizes
    int newH = 1 + (image_h+pad_l+pad_r-filter_h)/stride;
    int N = 1;
    int W = image_h;
    int FW = filter_h;
    int zPadWLeft = pad_l;
    int zPadWRight = pad_r;
    int strideW = stride;
    int newW = newH;
    int CI = inp_chans;
    int CO = out_chans; 

    int slot_count =  min(SEAL_POLY_MOD_DEGREE_MAX, max(8192, next_pow2(newH*newH)));

    ConvMetadata generalData;
    generalData.inp_chans = CI;
    generalData.image_h = image_h;
    generalData.image_w = W;
    generalData.filter_h = filter_h;
    generalData.filter_w = FW;
    generalData.stride_h = stride;
    generalData.stride_w = strideW;
    generalData.pad_t = pad_l;
    generalData.pad_b = pad_r;
    generalData.pad_l = zPadWLeft;
    generalData.pad_r = zPadWRight;
    generalData.output_h = newH;
    generalData.output_w = newW;    
    generalData.chans_per_cipher = slot_count / (newH * newW);

    //get the number of needed inputs in a batch
    
    int ct_halfNumOffServer = ceil(1.0 * num_relu / slot_count);
    int num_piggy = (ct_halfNumOffServer * slot_count - num_relu);    
    
    int slot_rmd = slot_count % (newH * newW);
    
    assert(((num_piggy != 0 ) && (slot_rmd != 0)) && "slot reminder is zero!");
    
    int batch_num;
    int PiggyInp = 0;
    int PiggyInf = 0;
    int numInp = 0;
    int cipherPerInp, InpPerRmd, numRmd;
    if(slot_rmd == 0){
        int gcd_tmp = GCD(num_piggy, num_relu);
        PiggyInp = num_piggy / gcd_tmp;
        numInp = num_relu / gcd_tmp;
        batch_num = numInp + PiggyInp;
    
    }else{
        cipherPerInp = ceil((1.0 * filter_h * FW * CI) / generalData.chans_per_cipher);
        InpPerRmd = ceil((1.0 * filter_h * FW * CI) / cipherPerInp);
        int gcd_on = GCD(newH * newW, slot_rmd);
        int PiggyInp_on = slot_rmd / gcd_on;
        int numRmd_on = newH * newW / gcd_on;
        int numInp_on = InpPerRmd * numRmd_on;
        //int batch_num_online = numInp_on + PiggyInp_on;
        
        int gcd_off = GCD(num_piggy, num_relu);
        int PiggyInp_off = num_piggy / gcd_off;
        int numInp_off = num_relu / gcd_off;
        //int batch_num_offline = numInp_off + PiggyInp_off;        
        
        int gcd_all = GCD(numInp_on, numInp_off);

        int piggy_one = PiggyInp_on * (numInp_off / gcd_all);
        int piggy_two = PiggyInp_off * (numInp_on / gcd_all);
        PiggyInp = max(piggy_one, piggy_two); 
        PiggyInf = min(piggy_one, piggy_two);
        
        numInp = numInp_on * (numInp_off / gcd_all);
        numRmd = numRmd_on * (numInp_off / gcd_all);        
        
        batch_num = numInp + PiggyInf;

    }
    
    if(verbose_info){
        cout << "[Public] the slot number: " << slot_count << " - # slot reminder for r0HAT: " << slot_rmd << endl;
        cout << "- # total input: " << batch_num << " - # piggybacked input: " << PiggyInf << endl;
        cout << "- # slot reminder for h1: " << num_piggy << " - # input per batch: " << numInp << endl;
        cout << "==================================================================" << endl;
    } 

    PRG128 prg;
    vector<vector<vector<vector<uint64_t>>>> piggyBatch_r0(PiggyInp);//the generated r0
    vector<vector<vector<vector<uint64_t>>>> filterArr(filter_h);
    Filters piggyBatchMod(PiggyInp);//the r0 used to perform im2col
    Image colR0(PiggyInp);//the transformed r0 after im2col
    Filters piggyX1(PiggyInp);//the pregenerated x1 for piggybaked inputs
    Filters piggyH1(PiggyInp);//the pregenerated h1 for piggybaked inputs
    Filters piggyPart1(PiggyInp);//the intermidiate values in first part for piggybaked inputs
    Filters piggyPart2(PiggyInp);//the partial output in second part for piggybaked inputs
    vector<vector<vector<uint64_t>>> piggyShare(PiggyInp);//the pregenerated share for piggy inputs
    Filters myFilters(CO); 
    Filters myFilters_pt(CO); 


    vector<vector<uint64_t>> outArr(CO);
    for(int i = 0; i < CO; i++){
        outArr[i].resize(newH * newW);
        for(int j = 0; j < (newH * newW); j++) {
            outArr[i][j] = 0;
        }
    }
    
    
    //the server generates its kernel
    if(party == SERVER) {
        for(int i = 0; i < filter_h; i++){
            filterArr[i].resize(FW);
            for(int j = 0; j < FW; j++) {
                filterArr[i][j].resize(CI);
                for(int k = 0; k < CI; k++) {
                    filterArr[i][j][k].resize(CO);
                    prg.random_data(filterArr[i][j][k].data(), CO * sizeof(uint64_t));
                    for(int h = 0; h < CO; h++) {
                        filterArr[i][j][k][h]
                            = ((int64_t) filterArr[i][j][k][h]) >> (64 - filter_precision);
                    }
                }
            }
        }
    }

    double offComm_total = 0, onComm_total = 0;
    double offTime_total = 0, onTime_total = 0;
    
    double offComm_totalp = 0, onComm_totalp = 0;
    double offTime_totalp = 0, onTime_totalp = 0;
    
    double offComm_recv = 0;
    double onComm_recv = 0;

    double offComm_recvp = 0;
    double onComm_recvp = 0;
    
    auto start_pre = clock_start();
    
    if(party == SERVER){
        //reconstruct the filter
#pragma omp parallel for num_threads(numThreads) schedule(static)         
        for (int out_c = 0; out_c < CO; out_c++) {
            Image tmp_img(CI);
            Image tmp_img1(CI);
            for (int inp_c = 0; inp_c < CI; inp_c++) {
                Channel tmp_chan(filter_h, FW);
                Channel tmp_chan1(filter_h, FW);
                for (int row = 0; row < filter_h; row++) {
                    for (int col = 0; col < FW; col++) {
                        tmp_chan(row, col) = neg_mod(filterArr[row][col][inp_c][out_c], (int64_t)prime_mod);
                        tmp_chan1(row, col) = (int64_t)filterArr[row][col][inp_c][out_c];
                    }
                }
                tmp_img[inp_c] = tmp_chan;
                tmp_img1[inp_c] = tmp_chan1;
            }
            myFilters[out_c] = tmp_img;
            myFilters_pt[out_c] = tmp_img1;
        } 
        
        //generate the shares for piggy input
        for(int i = 0; i < PiggyInp; i++){
            piggyShare[i].resize(CO);
            for(int pt_idx = 0; pt_idx < CO; pt_idx++) {
                piggyShare[i][pt_idx].resize(newH * newW);
                prg.random_mod_p<uint64_t>(piggyShare[i][pt_idx].data(), (newH * newW), prime_mod);
            }        
        }
           
    }
    
    
    if(slot_rmd != 0){//in case we need specific online batching
        if(party == CLIENT){
            //the client generates r0 for PiggyInp inputs
            for(int i = 0; i < PiggyInp; i++){
                uint64_t *r0 = new uint64_t[num_relu];
                prg.random_mod_p<uint64_t>(r0, num_relu, prime_mod);        
                //reshape r0
                Image r0_temp(CI);
                piggyBatch_r0[i].resize(CI);
                for (int chan = 0; chan < CI; chan++) {
                    piggyBatch_r0[i][chan].resize(image_h);
                    Channel tmp_chan(image_h, W);
                    for (int h = 0; h < image_h; h++) {
                        piggyBatch_r0[i][chan][h].resize(W);
                        for (int w = 0; w < W; w++) {
                            int idx = chan * image_h * W + h * W + w;
                            piggyBatch_r0[i][chan][h][w] = r0[idx];
                            tmp_chan(h, w) = neg_mod((int64_t)r0[idx], prime_mod);
                        }
                    }
                    r0_temp[chan] = tmp_chan;
                }
                piggyBatchMod[i] = r0_temp;
                //transform r0
                auto p_imageR0 = pad_image(generalData, r0_temp);
                const int col_heightR0 = generalData.filter_h * generalData.filter_w * generalData.inp_chans;
                const int col_widthR0 = generalData.output_h * generalData.output_w;
                Channel image_colR0(col_heightR0, col_widthR0);
                i2c(p_imageR0, image_colR0, generalData.filter_h, generalData.filter_w, generalData.stride_h, generalData.stride_w, generalData.output_h, generalData.output_w);
                colR0[i] = image_colR0;

                delete[] r0;
                
                //shape the partial output for piggybacked inputs
                Image p2_temp(CO);
                for (int chan = 0; chan < CO; chan++) {
                    Channel tmp_chan(newH, newW);
                    for (int h = 0; h < newH; h++) {
                        for (int w = 0; w < newW; w++) {
                            tmp_chan(h, w) = 0;
                        }
                    }
                    p2_temp[chan] = tmp_chan;
                }
                piggyPart2[i] = p2_temp;
                
                //shape piggyX and piggyH to store the computed share
                Image x_temp(CI);
                Image z_temp(CI);
                for (int chan = 0; chan < CI; chan++) {
                    Channel tmp_chanx(image_h, W);
                    Channel tmp_chanz(image_h, W);
                    for (int h = 0; h < image_h; h++) {
                        for (int w = 0; w < W; w++) {
                            tmp_chanx(h, w) = 0;
                            tmp_chanz(h, w) = 0;
                        }
                    }
                    x_temp[chan] = tmp_chanx;
                    z_temp[chan] = tmp_chanz;
                }
                piggyX1[i] = x_temp;
                piggyH1[i] = z_temp;
                
            }
        
        }else{//the server
            //generate the h1 and x1 for piggybacked inputs
            for(int i = 0; i < PiggyInp; i++){
                bool *h1 = new bool[num_relu];
                uint64_t *x1 = new uint64_t[num_relu];
                prg.random_bool(h1, num_relu);
                prg.random_mod_p<uint64_t>(x1, num_relu, prime_mod);        
                //reshape h1 and x1
                Image h1_temp(CI);
                Image x1_temp(CI);
                Image p1_temp(CI);
                for (int chan = 0; chan < CI; chan++) {
                    Channel tmp_chanX1(image_h, W);
                    Channel tmp_chanH1(image_h, W);
                    Channel tmp_chan(image_h, W);
                    for (int h = 0; h < image_h; h++) {
                        for (int w = 0; w < W; w++) {
                            int idx = chan * image_h * W + h * W + w;
                            tmp_chanX1(h, w) = x1[idx];
                            tmp_chanH1(h, w) = h1[idx];
                            tmp_chan(h, w) = 0;
                        }
                    }
                    x1_temp[chan] = tmp_chanX1;
                    h1_temp[chan] = tmp_chanH1;
                    p1_temp[chan] = tmp_chan;
                }
                piggyX1[i] = x1_temp;
                piggyH1[i] = h1_temp;
                piggyPart1[i] = p1_temp;

                delete[] h1;
                delete[] x1;
                
                //shape the partial output for piggybacked inputs
                Image p2_temp(CO);
                for (int chan = 0; chan < CO; chan++) {
                    Channel tmp_chan(newH, newW);
                    for (int h = 0; h < newH; h++) {
                        for (int w = 0; w < newW; w++) {
                            tmp_chan(h, w) = 0;
                        }
                    }
                    p2_temp[chan] = tmp_chan;
                }
                piggyPart2[i] = p2_temp;
                
            }        
        
        }
        
        //index to deal with individual element
        int piggyH1_cnt = 0;
        int piggyR_cnt = 0;
        
        long long t_pre = time_from(start_pre);
        offTime_total += (t_pre * 1.0 / 1000);
        
        for(int i = 0; i < numRmd; i++){
            int piggyRow_idx = 0;
            int piggyCol_offset = i * slot_rmd;
            for(int j = 0; j < InpPerRmd; j++){
                int piggy_rowOffset = j * cipherPerInp;
                
                //establish the connection
                io = new NetIO(party==1 ? nullptr:address.c_str(), port);
                
                auto start_off = clock_start();
                
                //set up the HE context
                shared_ptr<SEALContext> context_;
                Encryptor* encryptor_;
                Decryptor* decryptor_;
                Evaluator* evaluator_;
                BatchEncoder* encoder_;
                GaloisKeys* gal_keys_;
                Ciphertext* zero_;
                generate_new_keys(party, io, slot_count, context_, encryptor_, decryptor_, evaluator_, encoder_, gal_keys_, zero_);
                
                /************ Offline Broadcasting ***********/
                /********************************************/
                uint64_t offcomm_start = io->counter;
                vector<Ciphertext> enc_t1t2;
                //generate the share of x and DReLU
                uint64_t *x = new uint64_t[num_relu];//input share
                uint64_t *z = new uint64_t[num_relu];//boolean share
                
                uint64_t *piggy_x = new uint64_t[num_relu + num_piggy];
                uint64_t *piggy_z = new uint64_t[num_relu + num_piggy];
                uint64_t *piggy_r = new uint64_t[num_relu + num_piggy];
                    
                            
                uint64_t *r0, *piggy_setz, *piggy_setx, *piggy_setr;
                Image imageR0;
                
                vector<vector<uint64_t>> shr12off(CO, vector<uint64_t>(slot_count, 0ULL));
                
                vector<Ciphertext> enc_r0hat;  

                vector<Ciphertext> enc_Kr0(CO);       

                if(party == SERVER){
                    
                    //generate the share
                    for(int k = 0; k < CO; k++){
                        prg.random_mod_p<uint64_t>(shr12off[k].data(), slot_count, prime_mod);
                    }
                    
                    vector<Ciphertext> t1t2_ct(2 * ct_halfNumOffServer);//store the ciphertext pair
                    prg.random_mod_p<uint64_t>(x, num_relu, prime_mod);
                    bool *g1 = new bool[num_relu];
                    prg.random_bool(g1, num_relu);
                    for(int l = 0; l < num_relu; l++){
                        z[l] = g1[l];
                    }
                    delete[] g1;
#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for(int k = 0; k < ct_halfNumOffServer; k++){
                        vector<uint64_t> v1(slot_count, 0ULL);//it's first ciphertext in term 1
                        vector<uint64_t> v2(slot_count, 0ULL);//it's second ciphertext in term 2
                        Plaintext tmp1, tmp2;
                        int idx_offset = k * slot_count;
                        if(k == (ct_halfNumOffServer - 1)){
                            for(int l = 0; l < (num_relu - idx_offset); l++){
                                v1[l] = z[idx_offset + l];
                                if ((int64_t)z[idx_offset + l] == 0){
                                    v2[l] = neg_mod((int64_t)x[idx_offset + l], prime_mod);
                                }else{
                                    v2[l] = neg_mod(-(int64_t)x[idx_offset + l], prime_mod);
                                }
                            }
                            //make use of the wasted slots
                            if((num_relu - idx_offset) < slot_count){
                                piggy_setz = new uint64_t[num_piggy];
                                piggy_setx = new uint64_t[num_piggy];
                                int temp_idx = 0;
                                for(int l = (num_relu - idx_offset); l < slot_count; l++){
                                    int data_idx = piggyH1_cnt / num_relu;
                                    int chan_idx = (piggyH1_cnt / (image_h * W)) % CI;
                                    int row_idx = (piggyH1_cnt / W) % image_h;
                                    int col_idx = piggyH1_cnt % W;
                                    v1[l] = piggyH1[data_idx][chan_idx](row_idx, col_idx);
                                    piggy_setz[temp_idx] = piggyH1[data_idx][chan_idx](row_idx, col_idx);
                                    piggy_setx[temp_idx] = piggyX1[data_idx][chan_idx](row_idx, col_idx);
                                    if ((int64_t)piggyH1[data_idx][chan_idx](row_idx, col_idx) == 0){
                                        v2[l] = neg_mod((int64_t)piggyX1[data_idx][chan_idx](row_idx, col_idx), prime_mod);
                                    }else{
                                        v2[l] = neg_mod(-(int64_t)piggyX1[data_idx][chan_idx](row_idx, col_idx), prime_mod);
                                    }
                                    piggyH1_cnt++;
                                    temp_idx++;
                                }
                            }
                            
                            
                        }else{
                            for(int l = 0; l < slot_count; l++){
                                //fill the vectors 
                                v1[l] = z[idx_offset + l];
                                if ((int64_t)z[idx_offset + l] == 0){
                                    v2[l] = neg_mod((int64_t)x[idx_offset + l], prime_mod);
                                }else{
                                    v2[l] = neg_mod(-(int64_t)x[idx_offset + l], prime_mod);
                                }
                            }
                        }
                        encoder_->encode(v1, tmp1);
                        encoder_->encode(v2, tmp2);
                        encryptor_->encrypt(tmp1, t1t2_ct[k]);//it's h1
                        evaluator_->mod_switch_to_next_inplace(t1t2_ct[k]);
                        encryptor_->encrypt(tmp2, t1t2_ct[ct_halfNumOffServer + k]);//it's second ciphertext
                        evaluator_->mod_switch_to_next_inplace(t1t2_ct[ct_halfNumOffServer + k]);
                    }

                    //send the cipher to client
                    send_encrypted_vector(io, t1t2_ct);

                    if(verbose_info){
                        cout << "[Server] ciphertext pair {h1, x1(1-2(h1))} sent" << endl;
                    }
                    
                    
                    //recieve r0hat
                    const int col_hR0 = generalData.filter_h * generalData.filter_w * generalData.inp_chans;
                    const int col_wR0 = generalData.output_h * generalData.output_w;
                    const int f_size = generalData.filter_h * generalData.filter_w;
                    int chanPerCipher = generalData.chans_per_cipher;
                    int r0hat_ctNum = ceil(1.0 * col_hR0 / chanPerCipher);
                    
                    enc_r0hat.resize(r0hat_ctNum);
                    recv_encrypted_vector(io, enc_r0hat);
                    
                    if(verbose_info){
                        cout << "[Server] encrypted r0 hat received" << endl;
                    }

                    //compute the partial conv without rotation

#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for(int k = 0; k < CO; k++){
                        enc_Kr0[k] = *zero_;
                        evaluator_->mod_switch_to_next_inplace(enc_Kr0[k]);
                        for(int l = 0; l < r0hat_ctNum; l++){
                            vector<uint64_t> v_tmp(slot_count, 0ULL);
                            Plaintext tmp;
                            int chan_offset = l * chanPerCipher;
                            if(l == (r0hat_ctNum - 1)){
                                for(int m = 0; m < (col_hR0 - chan_offset); m++){
                                    int idx_offset = m * col_wR0;
                                    int idx_CI = (chan_offset + m) / f_size;
                                    int idx_FH = ((chan_offset + m) % f_size) / generalData.filter_w;
                                    int idx_FW = ((chan_offset + m) % f_size) % generalData.filter_w;
                                    vector<uint64_t> v = {0ULL, myFilters[k][idx_CI](idx_FH, idx_FW)};
                                    replace(v_tmp.begin() + idx_offset, v_tmp.begin() + idx_offset + col_wR0, v[0], v[1]);
                                      
                                }
                                //fill the kernel values for the piggy input
                                if((piggy_rowOffset + l) < col_hR0){
                                    int idx_CI = (piggy_rowOffset + l) / f_size;
                                    int idx_FH = ((piggy_rowOffset + l) % f_size) / generalData.filter_w;
                                    int idx_FW = ((piggy_rowOffset + l) % f_size) % generalData.filter_w;
                                    vector<uint64_t> v = {0ULL, myFilters[k][idx_CI](idx_FH, idx_FW)};
                                    int offset_tmp = slot_count - slot_rmd;
                                    replace(v_tmp.begin() + offset_tmp, v_tmp.end(), v[0], v[1]);
                                }
                                
                                
                                
                            }else{
                                for(int m = 0; m < chanPerCipher; m++){
                                    int idx_offset = m * col_wR0;
                                    int idx_CI = (chan_offset + m) / f_size;
                                    int idx_FH = ((chan_offset + m) % f_size) / generalData.filter_w;
                                    int idx_FW = ((chan_offset + m) % f_size) % generalData.filter_w;
                                    
                                    vector<uint64_t> v = {0ULL, myFilters[k][idx_CI](idx_FH, idx_FW)};
                                    replace(v_tmp.begin() + idx_offset, v_tmp.begin() + idx_offset + col_wR0, v[0], v[1]);
                                }
                                
                                //fill the kernel values for the piggy input
                                if((piggy_rowOffset + l) < col_hR0){
                                    int idx_CI = (piggy_rowOffset + l) / f_size;
                                    int idx_FH = ((piggy_rowOffset + l) % f_size) / generalData.filter_w;
                                    int idx_FW = ((piggy_rowOffset + l) % f_size) % generalData.filter_w;
                                    vector<uint64_t> v = {0ULL, myFilters[k][idx_CI](idx_FH, idx_FW)};
                                    int offset_tmp = slot_count - slot_rmd;
                                    replace(v_tmp.begin() + offset_tmp, v_tmp.end(), v[0], v[1]);
                                }
                                
                                
                            }                
                            
                            //encode the kernel vector
                            encoder_->encode(v_tmp, tmp);
                            //perform the multiplication
                            Ciphertext tmp_ct;
                            evaluator_->multiply_plain(enc_r0hat[l], tmp, tmp_ct);
                            //add the output
                            evaluator_->add_inplace(enc_Kr0[k], tmp_ct);            
                        }
                        
                        //add the noise
                        Plaintext tmp_res;
                        encoder_->encode(shr12off[k], tmp_res);
                        evaluator_->add_plain_inplace(enc_Kr0[k], tmp_res);
                    }                     

                
                }else{//the client
                    //generate r0
                    r0 = new uint64_t[num_relu];
                    prg.random_mod_p<uint64_t>(r0, num_relu, prime_mod);        
                    
                    //merge the generated r0 and the piggy one
                    if(num_piggy){
                        piggy_setr = new uint64_t[num_piggy];
                        //get the r0 of piggy input
                        for(int l = 0; l < num_piggy; l++){
                            int data_idx = piggyR_cnt / num_relu;
                            int chan_idx = (piggyR_cnt / (image_h * W)) % CI;
                            int row_idx = (piggyR_cnt / W) % image_h;
                            int col_idx = piggyR_cnt % W;
                            piggy_setr[l] = piggyBatch_r0[data_idx][chan_idx][row_idx][col_idx];
                            piggyR_cnt++;
                        }
                        
                    }
                    
                    
                    //transform r0 into r0hat and perform encryption
                    imageR0.resize(CI);
                    for (int chan = 0; chan < CI; chan++) {
                        Channel tmp_chan(image_h, W);
                        for (int h = 0; h < image_h; h++) {
                            for (int w = 0; w < W; w++) {
                                int idx = chan * image_h * W + h * W + w;
                                tmp_chan(h, w) = neg_mod((int64_t)r0[idx], prime_mod);
                            }
                        }
                        imageR0[chan] = tmp_chan;
                    }        
                    //transform r0
                    auto pd_imageR0 = pad_image(generalData, imageR0);
                    const int col_hR0 = generalData.filter_h * generalData.filter_w * generalData.inp_chans;
                    const int col_wR0 = generalData.output_h * generalData.output_w;
                    Channel img_colR0(col_hR0, col_wR0);
                    i2c(pd_imageR0, img_colR0, generalData.filter_h, generalData.filter_w, generalData.stride_h, generalData.stride_w, generalData.output_h, generalData.output_w);
                          
                    //encrypt r0hat
                    int chanPerCipher = generalData.chans_per_cipher;
                    int cipherNum = ceil(1.0 * col_hR0 / chanPerCipher);
                    vector<Ciphertext> r0hat_ct(cipherNum);    
#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for(int k = 0; k < cipherNum; k++){
                        vector<uint64_t> tmp_vec(slot_count, 0ULL);
                        Plaintext tmp_pt;
                        int chan_offset = k * chanPerCipher;
                        if(k == (cipherNum - 1)){
                            for(int l = 0; l < (col_hR0 - chan_offset); l++){
                                int len_offset = l * col_wR0;
                                for(int m = 0; m < col_wR0; m++){
                                    tmp_vec[len_offset + m] = img_colR0(chan_offset + l, m);
                                }
                            }
                            //make use of the wasted slots
                            if(piggyRow_idx < (filter_h * FW * CI)){
                                for(int tmp = 0; tmp < slot_rmd; tmp++){
                                    int cur_col = piggyCol_offset + tmp;
                                    int piggyChan_temp = cur_col / (newH * newW);
                                    int col_temp = cur_col % (newH * newW);
                                    int idx_start = slot_count - slot_rmd;
                                    tmp_vec[idx_start + tmp] = colR0[piggyChan_temp](piggyRow_idx, col_temp);
                                    
                                    
                                }
                                piggyRow_idx++;
                            }
                            
                            
                        }else{
                            for(int l = 0; l < chanPerCipher; l++){
                                int len_offset = l * col_wR0;
                                for(int m = 0; m < col_wR0; m++){
                                    tmp_vec[len_offset + m] = img_colR0(chan_offset + l, m);
                                }
                                
                            }
                            //make use of the wasted slots
                            if(piggyRow_idx < (filter_h * FW * CI)){
                                for(int tmp = 0; tmp < slot_rmd; tmp++){
                                    int cur_col = piggyCol_offset + tmp;
                                    int piggyChan_temp = cur_col / (newH * newW);
                                    int col_temp = cur_col % (newH * newW);
                                    int idx_start = slot_count - slot_rmd;
                                    tmp_vec[idx_start + tmp] = colR0[piggyChan_temp](piggyRow_idx, col_temp);
                                    
                                    
                                }
                                piggyRow_idx++;
                            }
                            
  
                        }
                        //encrypt the plaintext vector
                        encoder_->encode(tmp_vec, tmp_pt);
                        encryptor_->encrypt(tmp_pt, r0hat_ct[k]);
                        evaluator_->mod_switch_to_next_inplace(r0hat_ct[k]);
                    }
                    
                    //recieve h1 and x1(1-2(h2))
                    enc_t1t2.resize(2 * ct_halfNumOffServer);
                    recv_encrypted_vector(io, enc_t1t2);

                    if(verbose_info){
                        cout << "[Client] encrypted h1 and x1(1-2(h1)) received" << endl;
                    }

                    
                    //send the encrypted r0hat
                    send_encrypted_vector(io, r0hat_ct);
                    
                    if(verbose_info){
                        cout << "[Client] encrypted r0 hat sent" << endl;
                    }
                    


                }
                
                
                long long t_off = time_from(start_off);
                uint64_t offcomm_end = io->counter;

                cout << "Comm. Sent at offline (MiB): " << (offcomm_end - offcomm_start)/(1.0*(1ULL << 20)) << endl;
                cout <<"Offline Time (l=" << l << "; b=" << b << ") " << t_off * 1.0 / 1000 <<" ms"<< endl;
                
                offComm_total += ((offcomm_end - offcomm_start)/(1.0*(1ULL << 20)));
                offTime_total += (t_off * 1.0 / 1000);

                if(party == CLIENT){
                    //client sends the number of communication
                    uint64_t mySent = (offcomm_end - offcomm_start);
                    io->send_data(&mySent, sizeof(uint64_t));

                }else{//the server recieves the number
                    uint64_t myRecev = 0;
                    io->recv_data(&myRecev, sizeof(uint64_t));
                    offComm_recv += (myRecev / (1.0*(1ULL << 20)));
                    //cout << "Comm. Sent & Recv-ed at offline (MiB): " << (offcomm_end - offcomm_start + myRecev)/(1.0*(1ULL << 20)) << endl;
                }                                
                
                io->flush();
                
                delete io;
                
                cout <<"==================================================================" << endl;
                
                /***************** Online MSB ***************/
                /********************************************/
                //Setup IO and Base OTs
                for(int k = 0; k < numThreads; k++) {
                    ioArr[k] = new NetIO(party==1 ? nullptr:address.c_str(), port+k);
                    if (k == 0) {
                        otpackArr[k] = new OTPack<NetIO>(ioArr[k], party, b, l);
                    }else {
                        otpackArr[k] = new OTPack<NetIO>(ioArr[k], party, b, l, false);
                        otpackArr[k]->copy(otpackArr[0]);
                    }
                }
                if(verbose_info) std::cout << "All Base OTs Done" << std::endl;
                
                if(party == CLIENT){
                
                    prg.random_mod_p<uint64_t>(piggy_x, (num_relu+num_piggy), prime_mod);
                
                }
                
                //Fork Threads
                uint64_t comm_sent = 0;
	            uint64_t multiThreadedIOStart[numThreads];
	            for(int k = 0; k < numThreads; k++){
		            multiThreadedIOStart[k] = ioArr[k]->counter;
	            }
                auto start = clock_start();
                std::thread relu_threads[numThreads];
                
                for(int k = 0; k < (num_relu + num_piggy); k++){
                    if(k < num_relu){
                        if(party == SERVER){
                            piggy_x[k] = x[k];
                            piggy_z[k] = z[k];
                        }else{
                            piggy_r[k] = r0[k];
                        }
                        
                        
                    }else{
                        if(party == SERVER){
                            piggy_x[k] = piggy_setx[k - num_relu];
                            piggy_z[k] = piggy_setz[k - num_relu];
                        }else{
                            piggy_r[k] = piggy_setr[k - num_relu];
                        }
                        
                    }
                
                }
                
                int chunk_size = (num_relu + num_piggy)/numThreads;
                
                for (int k = 0; k < numThreads; ++k) {
                    int offset = k * chunk_size;
                    int lnum_relu;
                    if (k == (numThreads - 1)) {
                        lnum_relu = (num_relu + num_piggy) - offset;
                    } else {
                        lnum_relu = chunk_size;
                    }
                    relu_threads[k] = std::thread(field_relu_thread, k, piggy_z+offset, piggy_x+offset, lnum_relu);
                }
                for (int k = 0; k < numThreads; ++k) {
                    relu_threads[k].join();
                }
                long long t_msb = time_from(start);
	            for(int k = 0; k < numThreads; k++){
		            auto curComm = (ioArr[k]->counter) - multiThreadedIOStart[k];
		            comm_sent += curComm;
	            }
                cout <<"Comm. Sent for MSB (MiB): " << double(comm_sent)/(1.0*(1ULL<<20)) << std::endl;
                cout <<"Online Time for MSB (l=" << l << "; b=" << b << ") " << t_msb * 1.0 / 1000 <<" ms"<< endl;

                
                onComm_total += (double(comm_sent)/(1.0*(1ULL<<20)));
                onTime_total += (t_msb * 1.0 / 1000);

                if(party == CLIENT){
                    //client sends the number of communication
                    uint64_t mySent = comm_sent;
                    ioArr[0]->send_data(&mySent, sizeof(uint64_t));

                }else{//the server recieves the number
                    uint64_t myRecev = 0;
                    ioArr[0]->recv_data(&myRecev, sizeof(uint64_t));
                    onComm_recv += (myRecev / (1.0*(1ULL << 20)));
                    //cout << "Comm. Sent & Recv-ed for MSB (MiB): " << (comm_sent + myRecev)/(1.0*(1ULL << 20)) << endl;
                }

                
                //Verification
#if defined(DEBUG_EXEC)
                switch (party) {
                    case sci::ALICE: {//it's server
                        ioArr[0]->send_data(piggy_x, sizeof(uint64_t) * (num_relu + num_piggy));
                        ioArr[0]->send_data(piggy_z, sizeof(uint64_t) * (num_relu + num_piggy));
                        break;
                    }
                    case sci::BOB: {//it's client
                        uint64_t *xi = new uint64_t[num_relu + num_piggy];
                        uint64_t *zi = new uint64_t[num_relu + num_piggy];
                        ioArr[0]->recv_data(xi, sizeof(uint64_t) * (num_relu + num_piggy));
                        ioArr[0]->recv_data(zi, sizeof(uint64_t) * (num_relu + num_piggy));
                        
                        for(int k=0; k<(num_relu + num_piggy); k++){
                            xi[k] = (xi[k] + piggy_x[k]) % prime_mod;
                            zi[k] = (zi[k] + piggy_z[k]) % 2;//this recovers the MSB from two boolean shares
                            assert((zi[k] == (xi[k] > prime_mod/2))
                                    && "MSB protocol's answer is incorrect!");
                        }
                        
                        cout << GREEN << "[Client] Successful MSB Computing" << RESET << endl;
                        delete[] xi;
                        delete[] zi;
                        break;
                    }
                }
#endif                
                
                //Cleanup
                for (int k = 0; k < numThreads; k++) {
                    delete ioArr[k];
                    delete otpackArr[k];
                }
                cout <<"------------------------------------------------------------------" << endl;
                
                /********** Online Part after MSB ***********/
                /********************************************/
                io = new NetIO(party==1 ? nullptr:address.c_str(), port);
                
                uint64_t oncomm_start = io->counter;
                auto start_online = clock_start();
                
                if(party == CLIENT){
                    //compute the ciphertext
                    vector<Ciphertext> part_ct(ct_halfNumOffServer);
#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for(int k = 0; k < ct_halfNumOffServer; k++){
                        part_ct[k] = *zero_;
                        evaluator_->mod_switch_to_next_inplace(part_ct[k]);
                        vector<uint64_t> v1(slot_count, 0ULL);//it's h0
                        vector<uint64_t> v2(slot_count, 0ULL);//it's x0h0-r0
                        vector<uint64_t> v3(slot_count, 0ULL);//it's x0(1-2(h0))
                        Plaintext tmp1, tmp2, tmp3;
                        int idx_offset = k * slot_count;
                        //fill the vectors
                        for(int l = 0; l < slot_count; l++){
                            v1[l] = (piggy_z[idx_offset + l] ^ 1);//it's h0
                            if ((int64_t)piggy_z[idx_offset + l] == 0){
                                v2[l] = neg_mod((int64_t)piggy_x[idx_offset + l] - (int64_t)piggy_r[idx_offset + l], prime_mod);//it's x0h0-r0
                                v3[l] = neg_mod(-(int64_t)piggy_x[idx_offset + l], prime_mod);//it's x0(1-2(h0))
                                
                            }else{
                                v2[l] = neg_mod(-(int64_t)piggy_r[idx_offset + l], prime_mod);
                                v3[l] = neg_mod((int64_t)piggy_x[idx_offset + l], prime_mod);
                            }
                        }
                        
                        encoder_->encode(v1, tmp1);
                        encoder_->encode(v2, tmp2);
                        encoder_->encode(v3, tmp3);
                        Ciphertext tmp_ct1, tmp_ct2;
                        //multiply h1 with x0(1-2(h0))
                        evaluator_->multiply_plain(enc_t1t2[k], tmp3, tmp_ct1);

                        //multiply second ciphertext with h0
                        evaluator_->multiply_plain(enc_t1t2[k + ct_halfNumOffServer], tmp1, tmp_ct2);
                        
                        //add up the terms
                        evaluator_->add_inplace(part_ct[k], tmp_ct1);
                        evaluator_->add_inplace(part_ct[k], tmp_ct2);
                        evaluator_->add_plain_inplace(part_ct[k], tmp2);
                        evaluator_->mod_switch_to_next_inplace(part_ct[k]);
                    }                
                    
                    //the noise flooding that is needed for under-utilized ciphertext
#if 0                    
                    parms_id_type parms_id = part_ct[0].parms_id();
                    shared_ptr<const SEALContext::ContextData> context_data = context_->get_context_data(parms_id);        
#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for(int ct_idx = 0; ct_idx < ct_halfNumOffServer; ct_idx++) {
                        flood_ciphertext(part_ct[ct_idx], context_data, SMUDGING_BITLEN);
                        evaluator_->mod_switch_to_next_inplace(part_ct[ct_idx]);
                    }                    
#endif                    


                    //send the partial ciphertext
                    send_encrypted_vector(io, part_ct);

                    if(verbose_info){
                        cout << "[Client] partial ciphertext sent" << endl;
                    }        
                    
#if defined(DEBUG_EXEC)
                    GET_NOISE_BUDGET(decryptor_, part_ct[0], "Client", "after mod-switch");
#endif


                    //recieve the share ciphertext
                    vector<Ciphertext> ct_Kr0(CO);
                    recv_encrypted_vector(io, ct_Kr0);
                    
                    if(verbose_info){
                        cout << "[Client] output share received" << endl;
                    }                    
                    

                    //form the final share
                    vector<vector<uint64_t>> Kr0result(CO);
#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for (int ct_idx = 0; ct_idx < CO; ct_idx++) {
                        Plaintext tmp;
                        Kr0result[ct_idx].resize(slot_count);
                        decryptor_->decrypt(ct_Kr0[ct_idx], tmp);
                        encoder_->decode(tmp, Kr0result[ct_idx]);
                    }
                    
                    const int col_wid = generalData.output_h * generalData.output_w;
                    for(int k = 0; k < CO; k++) {
                        for(int l = 0; l < col_wid; l++) {
                            outArr[k][l] = Kr0result[k][l];
                            for(int m = 1; m < generalData.chans_per_cipher; m++) {
                                int idx_offset = m * col_wid;
                                outArr[k][l] = (outArr[k][l] + Kr0result[k][l + idx_offset]) % prime_mod;
                            }
                            outArr[k][l] = neg_mod((int64_t)outArr[k][l], prime_mod);
                        }
                        
                        //obtain the partial result of piggybacked input
                        int idx_first = slot_count - slot_rmd;
                        for(int l = 0; l < slot_rmd; l++){
                            int cur_col = piggyCol_offset + l;
                            int piggyNum_temp = cur_col / (newH * newW);
                            int piggyRow_temp = (cur_col % (newH * newW)) / newW;
                            int piggyCol_temp = (cur_col % (newH * newW)) % newW;
                            piggyPart2[piggyNum_temp][k](piggyRow_temp, piggyCol_temp) =  (piggyPart2[piggyNum_temp][k](piggyRow_temp, piggyCol_temp) + Kr0result[k][idx_first + l]) % prime_mod;
                            
                            piggyPart2[piggyNum_temp][k](piggyRow_temp, piggyCol_temp) = neg_mod((int64_t)piggyPart2[piggyNum_temp][k](piggyRow_temp, piggyCol_temp), prime_mod);
                        
                        }
                        
                    }
                    
                    if(verbose_info){cout << "[Client] output share decrypted and formed" << endl;}
                
                    
                    //verify the result
#if defined(DEBUG_EXEC)      
                    //form the input image
                    Image imageInp(CI);
                    for (int chan = 0; chan < CI; chan++) {
                        Channel tmp_chan(image_h, W);
                        for (int h = 0; h < image_h; h++) {
                            for (int w = 0; w < W; w++) {
                                int idx = chan * image_h * W + h * W + w;
                                tmp_chan(h, w) = neg_mod((int64_t)piggy_x[idx], prime_mod);
                            }
                        }
                        imageInp[chan] = tmp_chan;
                    }
                    
                    //send input share
                    for(int k = 0; k < CI; k++) {
                        io->send_data(imageInp[k].data(), image_h * W * sizeof(uint64_t));
                    }
                    
                    //store the share for piggy input
                    piggyH1_cnt += num_piggy;
                    int piggy_offset = piggyH1_cnt - num_piggy;
                    for(int l = 0; l < num_piggy; l++){
                        int data_idx = (piggy_offset + l) / num_relu;
                        int chan_idx = ((piggy_offset + l) / (image_h * W)) % CI;
                        int row_idx = ((piggy_offset + l) / W) % image_h;
                        int col_idx = (piggy_offset + l) % W;                        
                        piggyX1[data_idx][chan_idx](row_idx, col_idx) = neg_mod((int64_t)piggy_x[num_relu + l], prime_mod);
                        piggyH1[data_idx][chan_idx](row_idx, col_idx) = piggy_z[num_relu + l];
                        
                    }
                    
                    for(int l = 0; l < num_relu; l++){
                        z[l] = piggy_z[l];
                    }
                    
                    //send MSB share
                    io->send_data(z, sizeof(uint64_t) * num_relu); 
                    
                    //send final share
                    for(int l = 0; l < CO; l++) {
                        io->send_data(outArr[l].data(), sizeof(uint64_t) * col_wid);
                    }         
#endif                    
   
                
                
                }else{//the server

                    //sizes to perform the conv between r0 and kernel namely the rot-free computation with plaintext kernel
                    
                    const int col_hR0 = generalData.filter_h * generalData.filter_w * generalData.inp_chans;
                    const int col_wR0 = generalData.output_h * generalData.output_w;
                    const int f_size = generalData.filter_h * generalData.filter_w;
                    int chanPerCipher = generalData.chans_per_cipher;
                    int r0hat_ctNum = ceil(1.0 * col_hR0 / chanPerCipher);
                    
#if 0//we can also move the computation of k*r0 to online for a more resource-on-demanding process
                    vector<Ciphertext> enc_Kr0(CO);
#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for(int k = 0; k < CO; k++){
                        enc_Kr0[k] = *zero_;
                        evaluator_->mod_switch_to_next_inplace(enc_Kr0[k]);
                        for(int l = 0; l < r0hat_ctNum; l++){
                            vector<uint64_t> v_tmp(slot_count, 0ULL);
                            Plaintext tmp;
                            int chan_offset = l * chanPerCipher;
                            if(l == (r0hat_ctNum - 1)){
                                for(int m = 0; m < (col_hR0 - chan_offset); m++){
                                    int idx_offset = m * col_wR0;
                                    int idx_CI = (chan_offset + m) / f_size;
                                    int idx_FH = ((chan_offset + m) % f_size) / generalData.filter_w;
                                    int idx_FW = ((chan_offset + m) % f_size) % generalData.filter_w;
                                    vector<uint64_t> v = {0ULL, myFilters[k][idx_CI](idx_FH, idx_FW)};
                                    replace(v_tmp.begin() + idx_offset, v_tmp.begin() + idx_offset + col_wR0, v[0], v[1]);
                                      
                                }
                                //fill the kernel values for the piggy input
                                if((piggy_rowOffset + l) < col_hR0){
                                    int idx_CI = (piggy_rowOffset + l) / f_size;
                                    int idx_FH = ((piggy_rowOffset + l) % f_size) / generalData.filter_w;
                                    int idx_FW = ((piggy_rowOffset + l) % f_size) % generalData.filter_w;
                                    vector<uint64_t> v = {0ULL, myFilters[k][idx_CI](idx_FH, idx_FW)};
                                    int offset_tmp = slot_count - slot_rmd;
                                    replace(v_tmp.begin() + offset_tmp, v_tmp.end(), v[0], v[1]);
                                }
                                
                                
                                
                            }else{
                                for(int m = 0; m < chanPerCipher; m++){
                                    int idx_offset = m * col_wR0;
                                    int idx_CI = (chan_offset + m) / f_size;
                                    int idx_FH = ((chan_offset + m) % f_size) / generalData.filter_w;
                                    int idx_FW = ((chan_offset + m) % f_size) % generalData.filter_w;
                                    
                                    vector<uint64_t> v = {0ULL, myFilters[k][idx_CI](idx_FH, idx_FW)};
                                    replace(v_tmp.begin() + idx_offset, v_tmp.begin() + idx_offset + col_wR0, v[0], v[1]);
                                }
                                
                                //fill the kernel values for the piggy input
                                if((piggy_rowOffset + l) < col_hR0){
                                    int idx_CI = (piggy_rowOffset + l) / f_size;
                                    int idx_FH = ((piggy_rowOffset + l) % f_size) / generalData.filter_w;
                                    int idx_FW = ((piggy_rowOffset + l) % f_size) % generalData.filter_w;
                                    vector<uint64_t> v = {0ULL, myFilters[k][idx_CI](idx_FH, idx_FW)};
                                    int offset_tmp = slot_count - slot_rmd;
                                    replace(v_tmp.begin() + offset_tmp, v_tmp.end(), v[0], v[1]);
                                }
                                
                                
                            }                
                            
                            //encode the kernel vector
                            encoder_->encode(v_tmp, tmp);
                            //perform the multiplication
                            Ciphertext tmp_ct;
                            evaluator_->multiply_plain(enc_r0hat[l], tmp, tmp_ct);
                            //add the output
                            evaluator_->add_inplace(enc_Kr0[k], tmp_ct);            
                        }
                        
                        //add the noise
                        Plaintext tmp_res;
                        encoder_->encode(shr12off[k], tmp_res);
                        evaluator_->add_plain_inplace(enc_Kr0[k], tmp_res);
                    }                    
#endif

                    //receive the partial ciphertext
                    vector<Ciphertext> enc_part(ct_halfNumOffServer);
                    recv_encrypted_vector(io, enc_part);
                
                    if(verbose_info){
                        cout << "[Server] partial ciphertext received" << endl;
                    }
                    
                    //decrypt the partial ciphertext
                    vector<vector<uint64_t>> pt_part(ct_halfNumOffServer);
#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for (int ct_idx = 0; ct_idx < ct_halfNumOffServer; ct_idx++) {
                        Plaintext tmp;
                        pt_part[ct_idx].resize(slot_count);
                        decryptor_->decrypt(enc_part[ct_idx], tmp);
                        encoder_->decode(tmp, pt_part[ct_idx]);
                    }
                    if(verbose_info){cout << "[Server] partial ciphertext decrypted" << endl;}
                    
                    //form the image
                    Image imagePart1(CI);
                    for (int chan = 0; chan < CI; chan++) {
                        Channel tmp_chan(image_h, W);
                        for (int h = 0; h < image_h; h++) {
                            for (int w = 0; w < W; w++) {
                                int idx = chan * image_h * W + h * W + w;
                                tmp_chan(h, w) = neg_mod((int64_t)pt_part[idx / slot_count][idx % slot_count], prime_mod);
                                //add the term x1h1
                                if((int64_t)piggy_z[idx] == 1){
                                    tmp_chan(h, w) = neg_mod((int64_t)tmp_chan(h, w) + (int64_t)piggy_x[idx], prime_mod);
                                }
                            }
                        }
                        imagePart1[chan] = tmp_chan;
                    }                    
                
                    //pick out the piggy data
                    int pt_offset = slot_count - num_piggy;
                    int piggy_offset = piggyH1_cnt - num_piggy;
                    for(int l = 0; l < num_piggy; l++){
                        int data_idx = (piggy_offset + l) / num_relu;
                        int chan_idx = ((piggy_offset + l) / (image_h * W)) % CI;
                        int row_idx = ((piggy_offset + l) / W) % image_h;
                        int col_idx = (piggy_offset + l) % W;                        
                        piggyPart1[data_idx][chan_idx](row_idx, col_idx) = neg_mod((int64_t)pt_part[ct_halfNumOffServer - 1][pt_offset + l], prime_mod);
                        
                        //add the term x1h1
                        if((int64_t)piggy_z[num_relu + l] == 1){
                            piggyPart1[data_idx][chan_idx](row_idx, col_idx) = neg_mod((int64_t)piggyPart1[data_idx][chan_idx](row_idx, col_idx) + (int64_t)piggy_x[num_relu + l], prime_mod);
                        }
                        
                    }
                

                    //perform the convolution
                    Image conv_part1 = ideal_function(imagePart1, myFilters_pt, generalData);
                    
                    //add the convolution to the masked r0*k
#pragma omp parallel for num_threads(numThreads) schedule(static)                    
                    for(int chan_tmp = 0; chan_tmp < CO; chan_tmp++){
                        vector<uint64_t> v_tmp(slot_count, 0ULL);
                        for(int ht = 0; ht < newH; ht++){
                            for(int wt = 0; wt < newW; wt++){
                                int idx_tmp = ht * newW + wt;
                                v_tmp[idx_tmp] = neg_mod((int64_t)conv_part1[chan_tmp](ht, wt), prime_mod);
                            }
                        }
                        //encode the vector
                        Plaintext tmp_res;
                        encoder_->encode(v_tmp, tmp_res);

                        //add to the target ciphertext
                        evaluator_->add_plain_inplace(enc_Kr0[chan_tmp], tmp_res);      
                        evaluator_->mod_switch_to_next_inplace(enc_Kr0[chan_tmp]);                   
                    }

                    //the noise flooding that is needed for under-utilized ciphertext
#if 0
                    parms_id_type parms_id = enc_Kr0[0].parms_id();
                    shared_ptr<const SEALContext::ContextData> context_data
                    = context_->get_context_data(parms_id);        
#pragma omp parallel for num_threads(numThreads) schedule(static)
                    for(int ct_idx = 0; ct_idx < CO; ct_idx++) {
                        flood_ciphertext(enc_Kr0[ct_idx], context_data, SMUDGING_BITLEN);
                        evaluator_->mod_switch_to_next_inplace(enc_Kr0[ct_idx]);
                    }
#endif
              
                    //send the masked (r0*k)
                    send_encrypted_vector(io, enc_Kr0);

                    if(verbose_info){
                        cout << "[Server] encrypted share of output sent" << endl;
                    }

#if defined(DEBUG_EXEC)
                    GET_NOISE_BUDGET(decryptor_, enc_Kr0[0], "Server", "after mod-switch");
#endif

                
                    //form the share
                    for(int k = 0; k < CO; k++){
                        for(int l = 0; l < slot_count; l++){
                            shr12off[k][l] = neg_mod((int64_t)(prime_mod - shr12off[k][l]), prime_mod);
                        }
                    }
                    
                    for(int k = 0; k < CO; k++){
                        for(int l = 0; l < col_wR0; l++){
                            outArr[k][l] = shr12off[k][l];
                            for(int m = 1; m < chanPerCipher; m++) {
                                int idx_offset = m * col_wR0;
                                outArr[k][l] = (outArr[k][l] + shr12off[k][l + idx_offset]) % prime_mod;
                            }
                            outArr[k][l] = neg_mod((int64_t)outArr[k][l], prime_mod);
                        }
                    }

                    //pick out the share of second part for piggy inputs
                    int idx_first = slot_count - slot_rmd;
                    for(int k = 0; k < CO; k++){
                        for(int l = 0; l < slot_rmd; l++){
                            int cur_col = piggyCol_offset + l;
                            int piggyNum_temp = cur_col / (newH * newW);
                            int piggyRow_temp = (cur_col % (newH * newW)) / newW;
                            int piggyCol_temp = (cur_col % (newH * newW)) % newW;
                            piggyPart2[piggyNum_temp][k](piggyRow_temp, piggyCol_temp) =  (piggyPart2[piggyNum_temp][k](piggyRow_temp, piggyCol_temp) + shr12off[k][idx_first + l]) % prime_mod;
                            
                            piggyPart2[piggyNum_temp][k](piggyRow_temp, piggyCol_temp) = neg_mod((int64_t)piggyPart2[piggyNum_temp][k](piggyRow_temp, piggyCol_temp), prime_mod);
                        
                        }                    
                    }

                    
                    //verify the result
#if defined(DEBUG_EXEC)      
                    //receive input share
                    Image image_in(CI);
                    for(int k = 0; k < CI; k++) {
                        image_in[k].resize(image_h, W);
                        io->recv_data(image_in[k].data(), image_h * W * sizeof(uint64_t));
                    }   

                    //receive MSB share
                    uint64_t *zi = new uint64_t[num_relu];
                    io->recv_data(zi, sizeof(uint64_t) * num_relu);

                    //form the input image
                    for(int k = 0; k < CI; k++) {
                        for(int h = 0; h < image_h; h++) {
                            for(int w = 0; w < W; w++) {
                                int idx = k * image_h * W + h * W + w;
                                image_in[k](h,w) = (neg_mod((int64_t)piggy_x[idx], prime_mod) + image_in[k](h,w)) % prime_mod;
                                int drelu_tmp = (piggy_z[idx] + zi[idx] + 1) % 2;
                                image_in[k](h,w) = image_in[k](h,w) * drelu_tmp;
                            }
                        }
                    }
                    
                    //get the convolution
                    Image resultConv = ideal_function(image_in, myFilters_pt, generalData);

                    //receive final share
                    vector<vector<uint64_t>> outArr_0;
                    outArr_0.resize(CO);
                    for(int k = 0; k < CO; k++) {
                        outArr_0[k].resize(col_wR0);
                        io->recv_data(outArr_0[k].data(), sizeof(uint64_t) * col_wR0);
                    }

                    //get the result from final shares
                    for(int k = 0; k < CO; k++) {
                        for(int l = 0; l < col_wR0; l++) {
                            outArr_0[k][l] = (outArr_0[k][l] + outArr[k][l]) % prime_mod;
                        }
                    }

                    //compare the result
                    bool pass = true;
                    for (int k = 0; k < CO; k++) {
                        for (int l = 0; l < newH; l++) {
                            for (int m = 0; m < newW; m++) {
                                int idx = l * newW + m;
                                if (outArr_0[k][idx] != neg_mod(resultConv[k](l,m), (int64_t) prime_mod)){
                                    pass = false;
                                }
                            }
                        }
                    }

                    if (pass) {
                        cout << GREEN << "[Server] Successful Online Computing" << RESET << endl;
                    }
                    else {
                        cout << RED << "[Server] Failed Online Computing" << RESET << endl;
                        cout << RED << "WARNING: The implementation assumes that the computation" << endl;
                        cout << "performed by the server (on it's model and r0)" << endl;
                        cout << "fits in a 64-bit integer. The failed operation could be a result" << endl;
                        cout << "of overflowing the bound." << RESET << endl;
                    }

                    delete[] zi;
#endif

                
                }
                

                long long t_on = time_from(start_online);
                uint64_t oncomm_end = io->counter;
                cout << "Comm. Sent after MSB (MiB): " << (oncomm_end - oncomm_start)/(1.0*(1ULL << 20)) << endl;
                cout <<"Online Time after MSB (l=" << l << "; b=" << b << ") " << t_on * 1.0 / 1000 <<" ms"<< endl;  
                
                onComm_total += (double(oncomm_end - oncomm_start)/(1.0*(1ULL<<20)));
                onTime_total += (t_on * 1.0 / 1000);
                
                if(party == CLIENT){
                    //client sends the number of communication
                    uint64_t mySent = (oncomm_end - oncomm_start);
                    io->send_data(&mySent, sizeof(uint64_t));

                }else{//the server recieves the number
                    uint64_t myRecev = 0;
                    io->recv_data(&myRecev, sizeof(uint64_t));
                    onComm_recv += (myRecev / (1.0*(1ULL << 20)));
                    //cout << "Comm. Sent & Recv-ed after MSB (MiB): " << (oncomm_end - oncomm_start + myRecev)/(1.0*(1ULL << 20)) << endl;
                }                
                
                
                cout <<"------------------------------------------------------------------" << endl;
                
                cout << (i * InpPerRmd + j + 1) << " out of " << batch_num << " inputs computed " << endl;
                
                cout <<"==================================================================" << endl;                           

                
                io->flush();
                
                delete io;
                
                //clean the data
                delete[] x;
                delete[] z;
                
                delete[] piggy_x;
                delete[] piggy_z;
                delete[] piggy_r;
                
                if(party == CLIENT){
                    delete[] r0; 
                    if(num_piggy){
                        delete[] piggy_setr;
                    }
                    
                }else{
                    if(num_piggy){
                        delete[] piggy_setz;
                        delete[] piggy_setx;
                    }
                }
                free_keys(party, encryptor_, decryptor_, evaluator_, encoder_, gal_keys_, zero_);
                
                
            }
            
            
        }
        
        //no HE computation is needed for the piggy inputs
        io = new NetIO(party==1 ? nullptr:address.c_str(), port);
        
        //deal with the piggybacked inputs
        for(int j = 0; j < PiggyInf; j++){
            
            /******** Offline Part to Form Share ********/
            /********************************************/
            auto start_piggyoff = clock_start();
            if(party == SERVER){
                //add the piggy share to the computed one
                for(int k = 0; k < CO; k++){
                    for(int l = 0; l < newH; l++){
                        for(int m = 0; m < newW; m++){
                            int idx_tmp = l * newW + m;
                            piggyPart2[j][k](l, m) = neg_mod(((int64_t)piggyPart2[j][k](l, m) + (int64_t)(prime_mod - piggyShare[j][k][idx_tmp])), prime_mod);
                        }

                    }
                
                }
                
                if(verbose_info){
                    cout << "[Server] share for piggy input formed" << endl;
                }
                   
            }
            long long t_piggyoff = time_from(start_piggyoff);
            cout <<"Offline Time for Piggy Input (l=" << l << "; b=" << b << ") " << t_piggyoff * 1.0 / 1000 <<" ms"<< endl;
            
            offTime_totalp += (t_piggyoff * 1.0 / 1000);
            
            cout <<"==================================================================" << endl;            
            
            /******** Online Part to Form Share ********/
            /********************************************/            
            auto start_piggyon = clock_start();
            uint64_t oncomm_startpiggy = io->counter;
            
            if(party == SERVER){
                //perform the cnvolution
                Image local_piggyK = ideal_function(piggyPart1[j], myFilters_pt, generalData); 
                
                //add the noise
                for(int k = 0; k < CO; k++){
                    for(int l = 0; l < newH; l++){
                        for(int m = 0; m < newW; m++){
                            int idx_tmp = l * newW + m;
                            local_piggyK[k](l, m) = neg_mod(((int64_t)local_piggyK[k](l, m) + (int64_t)piggyShare[j][k][idx_tmp]), prime_mod);
                        }

                    }
                
                }
                                
                //send the share
                for(int i = 0; i < CO; i++) {
                    io->send_data(local_piggyK[i].data(), sizeof(uint64_t) * newH * newW);
                } 
                
                if(verbose_info){
                    cout << "[Server] share for piggy input sent" << endl;
                }
               
                
                //verify the result
#if defined(DEBUG_EXEC)                 
                //receive input share
                Image image_in(CI);
                for(int i = 0; i < CI; i++) {
                    image_in[i].resize(image_h, W);
                    io->recv_data(image_in[i].data(), image_h * W * sizeof(uint64_t));
                }                
                
                //receive MSB share
                Image msb_in(CI);
                for(int i = 0; i < CI; i++) {
                    msb_in[i].resize(image_h, W);
                    io->recv_data(msb_in[i].data(), image_h * W * sizeof(uint64_t));
                }                
                
                //form the input image
                for(int i = 0; i < CI; i++) {
                    for(int h = 0; h < image_h; h++) {
                        for(int w = 0; w < W; w++) {
                            image_in[i](h,w) = (neg_mod((int64_t)piggyX1[j][i](h,w), prime_mod) + image_in[i](h,w)) % prime_mod;
                            int drelu_tmp = (piggyH1[j][i](h,w) + msb_in[i](h,w) + 1) % 2;
                            image_in[i](h,w) = image_in[i](h,w) * drelu_tmp;
                        }
                    }
                }                
                
                //get the convolution
                Image resultConv = ideal_function(image_in, myFilters_pt, generalData);                
                
                //receive final share
                Image final_in(CO);
                for(int i = 0; i < CO; i++) {
                    final_in[i].resize(newH, newW);
                    io->recv_data(final_in[i].data(), newH * newW * sizeof(uint64_t));
                } 
                
                //get the result from final shares
                for(int i = 0; i < CO; i++) {
                    for(int h = 0; h < newH; h++) {
                        for(int w = 0; w < newW; w++) {
                            final_in[i](h, w) = (final_in[i](h, w) + piggyPart2[j][i](h, w)) % prime_mod;
                        }
                    }
                }
                
                //compare the result
                bool pass = true;
                for (int i = 0; i < CO; i++) {
                    for (int l = 0; l < newH; l++) {
                        for (int k = 0; k < newW; k++) {
                            if (final_in[i](l, k) != neg_mod(resultConv[i](l, k), (int64_t)prime_mod)){
                                pass = false;
                            }
                        }
                    }
                }                
                
                if (pass) {
                    cout << GREEN << "[Server] Successful Online for Piggy Input" << RESET << endl;
                }
                else {
                    cout << RED << "[Server] Failed Online for Piggy Input" << RESET << endl;
                    cout << RED << "WARNING: The implementation assumes that the computation" << endl;
                    cout << "performed by the server (on it's model and r0)" << endl;
                    cout << "fits in a 64-bit integer. The failed operation could be a result" << endl;
                    cout << "of overflowing the bound." << RESET << endl;
                }                                

#endif
            
            }else{//the client
                
                Image image_piggy(CO);
                for(int i = 0; i < CO; i++) {
                    image_piggy[i].resize(newH, newW);
                    io->recv_data(image_piggy[i].data(), newH * newW * sizeof(uint64_t));
                }            
                
                //form the final share
                for(int k = 0; k < CO; k++){
                    for(int l = 0; l < newH; l++){
                        for(int m = 0; m < newW; m++){
                            piggyPart2[j][k](l, m) = neg_mod(((int64_t)piggyPart2[j][k](l, m) + (int64_t)image_piggy[k](l, m)), prime_mod);
                        }

                    }
                
                }

                if(verbose_info){
                    cout << "[Client] share for piggy input received and formed" << endl;
                }


                //verify the result
#if defined(DEBUG_EXEC)                 
                //send the input share
                for(int i = 0; i < CI; i++) {
                    io->send_data(piggyX1[j][i].data(), image_h * W * sizeof(uint64_t));
                }
                
                //send the MSB share
                for(int i = 0; i < CI; i++) {
                    io->send_data(piggyH1[j][i].data(), image_h * W * sizeof(uint64_t));
                }                
                
                //send the final share
                for(int i = 0; i < CO; i++) {
                    io->send_data(piggyPart2[j][i].data(), sizeof(uint64_t) * newH * newW);
                }                 

#endif
            
            }            
            
            
            long long t_onpiggy = time_from(start_piggyon);
            uint64_t oncomm_endpiggy = io->counter;
            cout << "Comm. Sent for Piggy Input (MiB): " << (oncomm_endpiggy - oncomm_startpiggy)/(1.0*(1ULL << 20)) << endl;
            cout <<"Online Time for Piggy Input (l=" << l << "; b=" << b << ") " << t_onpiggy * 1.0 / 1000 <<" ms"<< endl;  
            
            onComm_totalp += (double(oncomm_endpiggy - oncomm_startpiggy)/(1.0*(1ULL<<20)));
            onTime_totalp += (t_onpiggy * 1.0 / 1000);
            
            if(party == CLIENT){
                //client sends the number of communication
                uint64_t mySent = (oncomm_endpiggy - oncomm_startpiggy);
                io->send_data(&mySent, sizeof(uint64_t));

            }else{//the server recieves the number
                uint64_t myRecev = 0;
                io->recv_data(&myRecev, sizeof(uint64_t));
                onComm_recvp += (myRecev / (1.0*(1ULL << 20)));
                //cout << "Comm. Sent & Recv-ed for piggy Inp. (MiB): " << (oncomm_endpiggy - oncomm_startpiggy + myRecev)/(1.0*(1ULL << 20)) << endl;
            }             
            
            
            cout <<"------------------------------------------------------------------" << endl;
            
            
            cout << (InpPerRmd * numRmd + j + 1) << " out of " << batch_num << " inputs (including " << j + 1 <<" piggy one) computed " << endl;
            
            cout <<"==================================================================" << endl;            
            
            
        }
        
        
        cout << "Main Input: Amortized Comm. Sent Offline (MiB): " << offComm_total / numInp << endl;
        if(party == SERVER){
            cout << "Main Input: Amortized Comm. Sent & Recv-ed Offline (MiB): " << (offComm_total + offComm_recv) / numInp << endl;
        }
        cout << "Main Input: Amortized Offline Time (l=" << l << "; b=" << b << ") " << offTime_total / numInp <<" ms"<< endl; 
        cout <<"------------------------------------------------------------------" << endl;
        cout << "          : Amortized Comm. Sent Online (MiB): " << onComm_total / numInp << endl;
        if(party == SERVER){
            cout << "Main Input: Amortized Comm. Sent & Recv-ed Online (MiB): " << (onComm_total + onComm_recv) / numInp << endl;
        }        
        cout << "          : Amortized Online Time (l=" << l << "; b=" << b << ") " << onTime_total / numInp <<" ms"<< endl;        
        cout <<"------------------------------------------------------------------" << endl;
        cout << "          : Amortized Comm. Sent (MiB): " << (offComm_total + onComm_total) / numInp << endl;
        if(party == SERVER){
            cout << "          : Amortized Comm. Sent & Recv-ed (MiB): " << (offComm_total + onComm_total + offComm_recv + onComm_recv) / numInp << endl;
        } 
        cout << "          : Amortized Time (l=" << l << "; b=" << b << ") " << (offTime_total + onTime_total) / numInp <<" ms"<< endl; 
        cout <<"------------------------------------------------------------------" << endl;
        cout << "Piggy Input: Amortized Comm. Sent (MiB): " << (offComm_totalp + onComm_totalp) / PiggyInf << endl;
        if(party == SERVER){
            cout << "Piggy Input: Amortized Comm. Sent and Recv-ed (MiB): " << (offComm_totalp + onComm_totalp + offComm_recvp + onComm_recvp) / PiggyInf << endl;
        }
        
        cout << "Piggy Input: Amortized Time (l=" << l << "; b=" << b << ") " << (offTime_totalp + onTime_totalp) / PiggyInf <<" ms"<< endl;
        cout <<"==================================================================" << endl;
        
        io->flush();
        
        delete io;
        

    }else{//in case we need specific offline batching
    
    
        //similar implementation is performed for offline batching, and so as for the input with size smaller than the slot number per cipher
    
    
    }


       
	return 0;
}
