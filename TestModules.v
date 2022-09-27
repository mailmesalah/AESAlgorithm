         
/*------------------------------------------------------------------------*/ 
  
  /*  Program for AES 128 bit Algorithm  */

    module AESAlgorithm(input  CLOCK,input RESET, input [127:0]IN ,output reg [7:0] out);
    
      
	reg [7:0]state[15:0];
	reg [7:0]cipherKey[15:0];
	reg [7:0]poly[15:0];
	reg [31:0]sBOx[255:0];

	reg[1:0] RoundState;
	reg[7:0] temp8b;
	reg [7:0]temp16x8b[15:0];

	integer i,j,index,x,y;

	function [7:0] gMul;
    	input [7:0] a,b;
	reg [7:0] p,hiBitSet;
    	integer i;

	begin
	
		p=8'b0;
		for(i=0;i<8;i=i+1)	
		begin
			if((b & 8'b00000001)==8'b00000001)
			begin
				p=p^a;
			end
			hiBitSet=(a & 8'b10000000);
			a=a<<1;
			if(hiBitSet==8'b10000000)
			begin
				a=a^8'b00011011;
			end
			b=b>>1;
		end
		gMul=p;
	end
  	endfunction

	always@(posedge CLOCK)
	begin

//Initialising State with Input Value
      					state[0]= IN[127:120];
        				state[1]= IN[119:112];
        				state[2]= IN[111:104];
        				state[3]= IN[103:96];
        				state[4]= IN[95:88];
        				state[5]= IN[87:80];
        				state[6]= IN[79:72];
        				state[7]= IN[71:64];
        				state[8]= IN[63:56];
					state[9]= IN[55:48];
        				state[10]= IN[47:40];
        				state[11]= IN[39:32];
        				state[12]= IN[31:24];
        				state[13]= IN[23:16];
        				state[14]= IN[15:8];
        				state[15]= IN[7:0];

					cipherKey[0]= IN[127:120];
        				cipherKey[1]= IN[119:112];
        				cipherKey[2]= IN[111:104];
        				cipherKey[3]= IN[103:96];
        				cipherKey[4]= IN[95:88];
        				cipherKey[5]= IN[87:80];
        				cipherKey[6]= IN[79:72];
        				cipherKey[7]= IN[71:64];
        				cipherKey[8]= IN[63:56];
					cipherKey[9]= IN[55:48];
        				cipherKey[10]= IN[47:40];
        				cipherKey[11]= IN[39:32];
        				cipherKey[12]= IN[31:24];
        				cipherKey[13]= IN[23:16];
        				cipherKey[14]= IN[15:8];
        				cipherKey[15]= IN[7:0];
				
				for(i=0;i<=3;i=i+1)
                        	begin															
					temp16x8b[i]=   gMul(state[i],2)^ gMul(state[i+4],3)^ gMul(state[i+8],1)^ gMul(state[i+12],1);
					temp16x8b[i+4]= gMul(state[i],1)^ gMul(state[i+4],2)^ gMul(state[i+8],3)^ gMul(state[i+12],1);
					temp16x8b[i+8]= gMul(state[i],1)^ gMul(state[i+4],1)^ gMul(state[i+8],2)^ gMul(state[i+12],3);
					temp16x8b[i+12]=gMul(state[i],3)^ gMul(state[i+4],1)^ gMul(state[i+8],1)^ gMul(state[i+12],2);
				end	
				//Copying the result value to state
				for(i=0;i<=15;i=i+1)
                        	begin
					state[i]=temp16x8b[i];
				end
	end
 endmodule