             
/*------------------------------------------------------------------------*/ 
  
  /*  Program for AES 128 bit Algorithm  */

    module AESAlgorithm(input  CLOCK,input RESET,input ED,,input DAVAILABLE,input [127:0]IN,input [127:0]KEY,output [127:0]OUT, output DONE );
    
      
	reg [7:0]state[15:0];
	reg [7:0]cipherKey[15:0];
	reg [7:0]sBOx[255:0];
	reg [7:0]rCon[9:0];

	reg[1:0] RoundState;
	reg[7:0] temp8b;
	reg [7:0]temp16x8b[15:0];
 
	localparam	Idle    = 2'b00,//Idle State                  	
                  	NineRound  = 2'b01,//2 to 9 round State
                  	LastRound = 2'b10;//10th round State
	integer i,j,round,x,y;

	/*****************************/
	//Multiplication in Rijndael's galois field
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

	/*****************************/

	//Initialising     
      	initial 
      	begin
		rCon[0]= 8'b00000001;
		rCon[1]= 8'b00000010;
        	rCon[2]= 8'b00000100;
        	rCon[3]= 8'b00001000;
        	rCon[4]= 8'b00010000;
        	rCon[5]= 8'b00100000;
        	rCon[6]= 8'b01000000;
        	rCon[7]= 8'b10000000;
        	rCon[8]= 8'b00011011;
        	rCon[9]= 8'b00110110;		

		RoundState=Idle;
      	end

	always@(posedge CLOCK)
	begin

		if(RESET==1'b1)
		begin
			RoundState=Idle;
			DONE=1'b0;
			round=0;
		end
		
		else if(ED==1'b1)
		begin		
			case (RoundState)
                                
                	Idle : //IDLE 
			begin
                                if(DAVAILABLE==1'b1)
				begin
					RoundState=NineRound;
					
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
		
					//Initialising Cipher Key with Key Value
      					cipherKey[0]= KEY[127:120];
        				cipherKey[1]= KEY[119:112];
        				cipherKey[2]= KEY[111:104];
        				cipherKey[3]= KEY[103:96];
        				cipherKey[4]= KEY[95:88];
        				cipherKey[5]= KEY[87:80];
        				cipherKey[6]= KEY[79:72];
        				cipherKey[7]= KEY[71:64];
        				cipherKey[8]= KEY[63:56];
					cipherKey[9]= KEY[55:48];
        				cipherKey[10]= KEY[47:40];
        				cipherKey[11]= KEY[39:32];
        				cipherKey[12]= KEY[31:24];
        				cipherKey[13]= KEY[23:16];
        				cipherKey[14]= KEY[15:8];
        				cipherKey[15]= KEY[7:0];

					//First AddRoundKey Operation
					for(i=0;i<=15;i=i+1)
                        		begin
                        			state[i]=state[i] ^ cipherKey[i];                        
                        		end					
				
					round=0;

				end
					
                        end                                
                	
			NineRound :
			begin
				round=round+1;

				//Operation Subbyte
				for(i=0;i<=15;i=i+1)
                        	begin
                        		temp8b=state[i];
                        		state[i]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];                        
                        	end
				
				//ShiftRows Operations
				for(i=1;i<=3;i=i+1)
                        	begin
                        		for(j=i*4;j<=(i*4)+3;j=j+1)
                        		begin
						index=j+i;
						if(index>((i*4)+3))
						begin
							index=index-4;
						end
                        			temp16x8b[j]=state[index];
                        		end	
                        	end
				//Copying shifted data to state
 				for(i=4;i<=15;i=i+1)
                        	begin
					state[i]=temp16x8b[i];
				end

				//MixColumn Operation
				//Matrix multiplication with the given Poly
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
	

				//KEY SCHEDULE Operation
				//Rotate last column
				temp8b=state[3];
				cypherKey[3]=cypherKey[7];
				cypherKey[7]=cypherKey[11];
				cypherKey[11]=cypherKey[15];
				cypherKey[15]=temp8b;
				
				//Substitute with SubBytes				
                        	temp8b=cypherKey[3];
                        	temp4x8b[0]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];                        
                        	temp8b=cypherKey[7];
                        	temp4x8b[1]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];
				temp8b=cypherKey[11];
                        	temp4x8b[2]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];
				temp8b=cypherKey[15];
                        	temp4x8b[3]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];
			
				//First operation of XORing
				cypherKey[0]=cypherKey[0] ^ temp4x8b[0] ^ rCon[round-1];
				cypherKey[4]=cypherKey[4] ^ temp4x8b[1] ^ 8'b00000000;
				cypherKey[8]=cypherKey[8] ^ temp4x8b[2] ^ 8'b00000000;
				cypherKey[12]=cypherKey[12] ^ temp4x8b[3] ^ 8'b00000000;
				
				//XORing other columns
				for(i=1;i<=3;i=i+1)
                        	begin
					cypherKey[i]=cypherKey[i-1] ^ cypherKey[i];
					cypherKey[i+4]=cypherKey[i+3] ^ cypherKey[i+4];
					cypherKey[i+8]=cypherKey[i+7] ^ cypherKey[i+8];
					cypherKey[i+12]=cypherKey[i+11] ^ cypherKey[i+12];
				end

				//ADD ROUND KEY OPERATION 
				for(i=0;i<=15;i=i+1)
                        	begin
                        		state[i]=state[i] ^ cipherKey[i];                        
                        	end
	
				//Move to next round if 9 round over
				if(round==9)
				begin
					RoundState=LastRound;
				end
						
			end
			
			LastRound :
			begin
				round=round+1;

				//Operation Subbyte
				for(i=0;i<=15;i=i+1)
                        	begin
                        		temp8b=state[i];
                        		state[i]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];                        
                        	end

				//ShiftRows Operations
				for(i=1;i<=3;i=i+1)
                        	begin
                        		for(j=i*4;j<=(i*4)+3;j=j+1)
                        		begin
						index=j+i;
						if(index>((i*4)+3))
						begin
							index=index-4;
						end
                        			temp16x8b[j]=state[index];
                        		end	
                        	end
				//Copying shifted data to state
 				for(i=4;i<=15;i=i+1)
                        	begin
					state[i]=temp16x8b[i];
				end
				

				//KEY SCHEDULE Operation
				//Rotate last column
				temp8b=state[3];
				cypherKey[3]=cypherKey[7];
				cypherKey[7]=cypherKey[11];
				cypherKey[11]=cypherKey[15];
				cypherKey[15]=temp8b;
				
				//Substitute with SubBytes				
                        	temp8b=cypherKey[3];
                        	temp4x8b[0]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];                        
                        	temp8b=cypherKey[7];
                        	temp4x8b[1]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];
				temp8b=cypherKey[11];
                        	temp4x8b[2]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];
				temp8b=cypherKey[15];
                        	temp4x8b[3]=sBox[((temp8b[7:4]*15)+temp8b[3:0])];
			
				//First operation of XORing
				cypherKey[0]=cypherKey[0] ^ temp4x8b[0] ^ rCon[round-1];
				cypherKey[4]=cypherKey[4] ^ temp4x8b[1] ^ 8'b00000000;
				cypherKey[8]=cypherKey[8] ^ temp4x8b[2] ^ 8'b00000000;
				cypherKey[12]=cypherKey[12] ^ temp4x8b[3] ^ 8'b00000000;
				
				//XORing other columns
				for(i=1;i<=3;i=i+1)
                        	begin
					cypherKey[i]=cypherKey[i-1] ^ cypherKey[i];
					cypherKey[i+4]=cypherKey[i+3] ^ cypherKey[i+4];
					cypherKey[i+8]=cypherKey[i+7] ^ cypherKey[i+8];
					cypherKey[i+12]=cypherKey[i+11] ^ cypherKey[i+12];
				end

				//ADD ROUND KEY OPERATION 
				for(i=0;i<=15;i=i+1)
                        	begin
                        		state[i]=state[i] ^ cipherKey[i];                        
                        	end

				//Finilise
				OUT[127:120]=state[0];
        			OUT[119:112]=state[1];
        			OUT[111:104]=state[2];
        			OUT[103:96]=state[3];
        			OUT[95:88]=state[4];
        			OUT[87:80]=state[5];
        			OUT[79:72]=state[6];
        			OUT[71:64]=state[7];
        			OUT[63:56]=state[8];
				OUT[55:48]=state[9];
        			OUT[47:40]=state[10];
        			OUT[39:32]=state[11];
        			OUT[31:24]=state[12];
        			OUT[23:16]=state[13];
        			OUT[15:8]=state[14];
        			OUT[7:0]=state[15];
				DONE=1'b1;
				RoundState=Idle;
				
			end

                	//Default  
                	default     : 
			begin
                             
                              	
			end		
		
              		endcase
		end

	end
      
    endmodule
/*------------------------------------------------------------------------*/ 
