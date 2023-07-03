from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.


class SiteAdmin(AbstractUser):
    """
    网站管理员
    """
    role = models.CharField('权限', max_length=64, default='')

    def __str__(self):
        return str(self.username)


class Prize(models.Model):
    """礼品模型类"""
    code = models.IntegerField(default=None, verbose_name='礼品编号')
    prize_name = models.CharField(max_length=64, verbose_name='礼品名称')
    probability = models.IntegerField('中奖概率', default=0)
    grade = models.CharField('分类', max_length=32)

    class Meta:
        verbose_name = '奖品管理'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.prize_name


class Rule(models.Model):
    """
    内定规则
    """
    user = models.CharField('活动用户', max_length=32)
    sequence = models.CharField('顺序', max_length=64, default='', blank=True)
    flag = models.IntegerField('标记', default=1)
    score = models.IntegerField("活动次数", default=0)
    addTime = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    type = models.CharField('类别', max_length=32, default='默认')

    def get_order(self):
        if self.sequence.strip() == '':
            return None
        order_list = self.sequence.split(',')
        if 0 < self.flag <= len(order_list):
            order = order_list[self.flag-1]
            self.flag = self.flag + 1
            if order.strip() == '?':
                return None
            else:
                return int(order)
        else:
            return None

    class Meta:
        verbose_name = '用户设定'
        verbose_name_plural = verbose_name

    def __str__(self):
        return str(self.user)


class Rec(models.Model):
    """
    活动记录
    """
    TYPE_CHOICES = (
        (0, "自然抽奖"),
        (1, "内定抽奖"),
        (2, "后台添加")
    )
    SEND_CHOICES = (
        (0, "未派送"),
        (1, "已派送"),
        (2, "锁定")
    )
    user = models.CharField('活动用户', max_length=32)
    prizeName = models.CharField('奖品名称', max_length=64)
    prizeId = models.IntegerField('奖品ID', null=True, default=None)
    datetime = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    sendTime = models.DateTimeField(verbose_name='发送时间', null=True, default=None)
    isSend = models.IntegerField('是否发送', choices=SEND_CHOICES, default=0)
    censor = models.CharField('派送人', max_length=32, null=True)
    ip = models.GenericIPAddressField(verbose_name='抽奖IP')
    type = models.IntegerField('抽奖方式', choices=TYPE_CHOICES, default=0)

    class Meta:
        verbose_name = '活动记录'
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.user+"#"+self.prizeName


class Info(models.Model):
    """
    活动时间、文本配置
    """
    name = models.CharField(max_length=32, verbose_name='活动名称', default='请设置活动名称')
    is_open = models.BooleanField(default=False, verbose_name='是否开启')
    errmsg = models.CharField(max_length=100, verbose_name='关闭提示', default='活动还未开启')
    start_time = models.DateTimeField(verbose_name='开始时间', null=True, default=None)
    end_time = models.DateTimeField(verbose_name='结束时间', null=True, default=None)
    day_start = models.TimeField('日启', null=True, default=None)
    day_end = models.TimeField('日结', null=True, default=None)
