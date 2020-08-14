package burp;

import java.util.Random;

public class RandomIP {
	
	public static String RandomIPstr() {
		Random r = new Random(System.currentTimeMillis()-1);
		String IPstr = Integer.toString(r.nextInt(255));
		for(int i=0; i<3; i++){
			Random ran = new Random(System.currentTimeMillis()+i);
			int ra = ran.nextInt(255);
			IPstr = IPstr+"."+Integer.toString(ra);
		}
		return IPstr;
	}
	public static void main(String[] args){
		System.out.println(RandomIPstr());
	}
}

