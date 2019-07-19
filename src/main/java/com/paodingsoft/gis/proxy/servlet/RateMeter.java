package com.paodingsoft.gis.proxy.servlet;
import java.util.Date;

/**
 * @author Christopher C. Perry &lt;perrych2@msu.edu&gt;
 * ported from https://github.com/Esri/resource-proxy
*/
public class RateMeter {
  double _rate; //internal rate is stored in requests per second
  int _countCap;
  double _count = 0;
  long _lastUpdate = new Date().getTime();

  public RateMeter(int rateLimit, int rateLimitPeriod){
    this._rate = (double) rateLimit / rateLimitPeriod / 60;
    this._countCap = rateLimit;
  }

  //called when rate-limited endpoint is invoked
  public boolean click() {
    long ts = (new Date().getTime() - _lastUpdate) / 1000;
    this._lastUpdate = new Date().getTime();
    //assuming uniform distribution of requests over time,
    //reducing the counter according to # of seconds passed
    //since last invocation
    this._count = Math.max(0, this._count - ts * this._rate);
    if (this._count <= this._countCap) {
      //good to proceed
      this._count++;
      return true;
    }
    return false;
  }

  public boolean canBeCleaned() {
    long ts = (new Date().getTime() - this._lastUpdate) / 1000;
    return this._count - ts * this._rate <= 0;
  }
  
}
