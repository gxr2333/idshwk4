@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string) {
    SumStats::observe("response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if (code == 404) {
        SumStats::observe("response404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}

event zeek_init() {
    local res_all = SumStats::Reducer($stream="response", $apply=set(SumStats::SUM));
    local res_404 = SumStats::Reducer($stream="response404", $apply=set(SumStats::SUM,SumStats::UNIQUE));
    # 创建统计
    SumStats::create([$name="Detect_scan_by_404", 
                      $epoch=10min, 
                      $reducers=set(res_all, res_404), 
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
                        {
                            # 首先取得Reducer统计结果
                            local r_all = result["response"];
                            local r_404 = result["response404"];
                            if (r_404$sum > 2 && r_404$sum / r_all$sum > 0.2 && r_404$unique / r_404$sum > 0.5)
                            # if (r_404$num > 2 && (10*r_404$num / r_all$num) > 2 && (10*r_404$unique / r_404$num) > 5) 
                            {
                                print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, r_404$sum, r_404$unique);
                            } 
                        }
                    ]);
}